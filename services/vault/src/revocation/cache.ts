import {
  didWebToResolutionUrl,
  verifyRevocationTombstone,
  type DidWebDocument,
} from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";

export type AcceptTombstoneError =
  | { readonly code: "UNVERIFIABLE_ISSUER"; readonly reason: string }
  | { readonly code: "INVALID_TOMBSTONE"; readonly reason: string };

export interface RevocationCacheStatus {
  readonly revokedCount: number;
  readonly freshAsOf: string | null;
  readonly stale: boolean;
}

/**
 * The hot path's local view of who has been revoked (CLAUDE.md section 3:
 * "the hot path reads locally and never blocks on the cold path"). Updated
 * by pushed tombstones from the revocation service and by a periodic resync;
 * `isRevoked` is an in-memory set lookup, no database or network.
 *
 * Bounded staleness is deliberate and explicit. If no resync has succeeded
 * within `maxStalenessMs`, the cache reports itself stale and the caller
 * denies — a brief control-plane outage must not silently turn into
 * indefinite trust in a possibly-outdated allow list.
 */
export interface RevocationCache {
  isRevoked(agentDid: string): boolean;
  isStale(now: Date): boolean;
  status(now: Date): RevocationCacheStatus;
  acceptTombstone(tombstone: string, now: Date): Promise<Result<string, AcceptTombstoneError>>;
  resync(now: Date): Promise<Result<number, AcceptTombstoneError>>;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Resolves the revocation service's own DID document once and caches the key.
 * Tombstones arrive on an unauthenticated endpoint, so an unverified one is
 * worthless: without this check anyone who can reach the vault could revoke
 * any agent.
 */
function createIssuerKeyResolver(params: {
  readonly issuerDid: string;
  readonly fetchImpl: typeof fetch;
  readonly timeoutMs: number;
}) {
  let cached: Uint8Array | null = null;

  return async (): Promise<Result<Uint8Array, AcceptTombstoneError>> => {
    if (cached) return ok(cached);
    const url = didWebToResolutionUrl(params.issuerDid);
    try {
      const response = await params.fetchImpl(url, {
        signal: AbortSignal.timeout(params.timeoutMs),
      });
      if (!response.ok) {
        return err({ code: "UNVERIFIABLE_ISSUER", reason: `${url}: HTTP ${response.status}` });
      }
      const didDocument = (await response.json()) as DidWebDocument;
      const multibase = didDocument.verificationMethod?.[0]?.publicKeyMultibase;
      if (typeof multibase !== "string" || !multibase.startsWith("z")) {
        return err({
          code: "UNVERIFIABLE_ISSUER",
          reason: `${url}: no usable verification method`,
        });
      }
      // Strip multibase "z" and the 2-byte multicodec ed25519-pub header.
      cached = decodeBase58(multibase.slice(1)).slice(2);
      return ok(cached);
    } catch (error) {
      return err({ code: "UNVERIFIABLE_ISSUER", reason: `${url}: ${errorMessage(error)}` });
    }
  };
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function decodeBase58(input: string): Uint8Array {
  const bytes: number[] = [];
  for (const char of input) {
    let carry = BASE58_ALPHABET.indexOf(char);
    if (carry < 0) throw new Error(`invalid base58 character: ${char}`);
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i]! * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of input) {
    if (char !== "1") break;
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}

export function createRevocationCache(params: {
  readonly issuerDid: string;
  readonly revocationUrl: string;
  readonly maxStalenessMs: number;
  readonly onRevoked?: (agentDid: string) => Promise<void>;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}): RevocationCache {
  const {
    issuerDid,
    revocationUrl,
    maxStalenessMs,
    onRevoked,
    fetchImpl = fetch,
    timeoutMs = 2_000,
  } = params;

  const revoked = new Set<string>();
  let freshAsOf: Date | null = null;
  const resolveIssuerKey = createIssuerKeyResolver({ issuerDid, fetchImpl, timeoutMs });

  async function accept(
    tombstone: string,
    now: Date,
  ): Promise<Result<string, AcceptTombstoneError>> {
    const publicKey = await resolveIssuerKey();
    if (!publicKey.ok) return publicKey;

    const verified = verifyRevocationTombstone({ tombstone, publicKey: publicKey.value });
    if (!verified.ok) {
      return err({ code: "INVALID_TOMBSTONE", reason: verified.error.code });
    }

    const { agentDid } = verified.value;
    const isNew = !revoked.has(agentDid);
    revoked.add(agentDid);
    freshAsOf = now;
    // Fan out to the tool adapters only the first time, so a re-broadcast
    // does not re-hit every connector.
    if (isNew && onRevoked) await onRevoked(agentDid);
    return ok(agentDid);
  }

  return {
    isRevoked: (agentDid) => revoked.has(agentDid),

    isStale(now) {
      if (freshAsOf === null) return true;
      return now.getTime() - freshAsOf.getTime() > maxStalenessMs;
    },

    status(now) {
      return {
        revokedCount: revoked.size,
        freshAsOf: freshAsOf?.toISOString() ?? null,
        stale: freshAsOf === null || now.getTime() - freshAsOf.getTime() > maxStalenessMs,
      };
    },

    acceptTombstone: accept,

    async resync(now) {
      const url = `${revocationUrl.replace(/\/$/, "")}/revocations`;
      let tombstones: readonly string[];
      try {
        const response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
        if (!response.ok) {
          return err({ code: "UNVERIFIABLE_ISSUER", reason: `${url}: HTTP ${response.status}` });
        }
        const body = (await response.json()) as { tombstones?: unknown };
        if (!Array.isArray(body.tombstones)) {
          return err({ code: "UNVERIFIABLE_ISSUER", reason: `${url}: malformed resync payload` });
        }
        tombstones = body.tombstones as readonly string[];
      } catch (error) {
        return err({ code: "UNVERIFIABLE_ISSUER", reason: `${url}: ${errorMessage(error)}` });
      }

      for (const tombstone of tombstones) {
        const accepted = await accept(tombstone, now);
        // A single bad entry must not abort the resync: the rest of the
        // revocations are still worth applying.
        if (!accepted.ok && accepted.error.code === "UNVERIFIABLE_ISSUER") return accepted;
      }
      // An empty list is still a successful sync — it means nobody is
      // revoked, which is exactly as fresh as a list with entries.
      freshAsOf = now;
      return ok(tombstones.length);
    },
  };
}

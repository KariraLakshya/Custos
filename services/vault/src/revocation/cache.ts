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
 * Minimum gap between re-resolutions of the issuer's DID document. The push
 * endpoint is unauthenticated, so without it a flood of forged tombstones
 * would become a flood of fetches against the revocation service.
 */
const KEY_REFRESH_MIN_INTERVAL_MS = 5_000;

/**
 * Resolves the revocation service's own DID document and caches the key.
 * Tombstones arrive on an unauthenticated endpoint, so an unverified one is
 * worthless: without this check anyone who can reach the vault could revoke
 * any agent.
 *
 * `refresh` re-resolves after the key may have rotated (the revocation
 * service's key changes on restart). Trust is unchanged: the key still comes
 * only from the issuer's own did:web URL. Rate-limited, see above.
 */
function createIssuerKeyResolver(params: {
  readonly issuerDid: string;
  readonly fetchImpl: typeof fetch;
  readonly timeoutMs: number;
}) {
  let cached: Uint8Array | null = null;
  let lastResolvedAt: number | null = null;

  async function fetchKey(now: Date): Promise<Result<Uint8Array, AcceptTombstoneError>> {
    lastResolvedAt = now.getTime();
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
  }

  return {
    current: async (now: Date): Promise<Result<Uint8Array, AcceptTombstoneError>> =>
      cached ? ok(cached) : fetchKey(now),

    /** A freshly resolved key, or null if rate-limited or resolution failed. */
    async refresh(now: Date): Promise<Uint8Array | null> {
      if (lastResolvedAt !== null && now.getTime() - lastResolvedAt < KEY_REFRESH_MIN_INTERVAL_MS) {
        return null;
      }
      const resolved = await fetchKey(now);
      return resolved.ok ? resolved.value : null;
    },
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

  async function apply(
    tombstone: string,
    now: Date,
    markFresh: boolean,
  ): Promise<Result<string, AcceptTombstoneError>> {
    const publicKey = await resolveIssuerKey.current(now);
    if (!publicKey.ok) return publicKey;

    let verified = verifyRevocationTombstone({ tombstone, publicKey: publicKey.value });
    if (!verified.ok) {
      // The issuer may have rotated its key since it was cached: re-resolve
      // once and retry before rejecting.
      const refreshed = await resolveIssuerKey.refresh(now);
      if (refreshed) verified = verifyRevocationTombstone({ tombstone, publicKey: refreshed });
    }
    if (!verified.ok) {
      return err({ code: "INVALID_TOMBSTONE", reason: verified.error.code });
    }

    const { agentDid } = verified.value;
    const isNew = !revoked.has(agentDid);
    revoked.add(agentDid);
    if (markFresh) freshAsOf = now;
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

    acceptTombstone: (tombstone, now) => apply(tombstone, now, true),

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

      let unverifiable: AcceptTombstoneError | null = null;
      for (const tombstone of tombstones) {
        const accepted = await apply(tombstone, now, false);
        if (accepted.ok) continue;
        if (accepted.error.code === "UNVERIFIABLE_ISSUER") return accepted;
        // A single bad entry must not stop the rest being applied, but the
        // list is then incomplete: it may be missing a revocation, so it
        // must not count as fresh. Bounded staleness then fails closed.
        unverifiable ??= accepted.error;
      }
      if (unverifiable) return err(unverifiable);
      // An empty list is still a successful sync — it means nobody is
      // revoked, which is exactly as fresh as a list with entries.
      freshAsOf = now;
      return ok(tombstones.length);
    },
  };
}

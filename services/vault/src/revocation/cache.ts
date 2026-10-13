import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_ENTRY_TYPE,
  BITSTRING_STATUS_LIST_TYPE,
  decodeStatusList,
  didWebToResolutionUrl,
  isRevoked as isBitSet,
  verifyCredential,
  verifyRevocationTombstone,
  type DidWebDocument,
  type SignedCredential,
} from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";

export type IssuerError = { readonly code: "UNVERIFIABLE_ISSUER"; readonly reason: string };

export type AcceptTombstoneError =
  IssuerError | { readonly code: "INVALID_TOMBSTONE"; readonly reason: string };

export type ResyncError =
  | IssuerError
  | { readonly code: "INVALID_STATUS_LIST"; readonly reason: string }
  | { readonly code: "STATUS_LIST_OUT_OF_BOUNDS"; readonly reason: string };

export type TrackAgentError = {
  readonly code: "INVALID_CREDENTIAL_STATUS";
  readonly reason: string;
};

/**
 * What the local view says about one agent. `unknown` is its own answer, not
 * "not revoked": a view that has never been told which bit is this agent's
 * cannot vouch for it, so the caller denies (fail closed).
 */
export type AgentVerdict = "ok" | "revoked" | "unknown";

export interface RevocationCacheStatus {
  readonly revokedCount: number;
  readonly freshAsOf: string | null;
  readonly stale: boolean;
}

/**
 * The hot path's local view of who has been revoked (CLAUDE.md section 3:
 * "the hot path reads locally and never blocks on the cold path"). Two inputs
 * feed it: pushed tombstones (fast, one agent each) and a periodic resync
 * from the signed status list (ADR 0013). `verdict` is an in-memory lookup,
 * no database or network.
 *
 * Bounded staleness is deliberate and explicit. The freshness of the view is
 * the signed `validFrom` of the newest list applied, never the time it was
 * received, so replaying an old list cannot buy a fresh window. If it is
 * older than `maxStalenessMs` (plus the allowed clock skew) the cache reports
 * itself stale and the caller denies.
 */
export interface RevocationCache {
  verdict(agentDid: string): AgentVerdict;
  /**
   * Records which status list bit is this agent's, from the `credentialStatus`
   * entry of its credential. The caller has already verified the credential's
   * signature and the agent's proof of possession; this checks that the entry
   * points at the list this cache trusts and carries a well-formed index.
   */
  trackAgent(
    agentDid: string,
    credentialStatus: unknown,
    now: Date,
  ): Result<undefined, TrackAgentError>;
  isStale(now: Date): boolean;
  status(now: Date): RevocationCacheStatus;
  acceptTombstone(tombstone: string, now: Date): Promise<Result<string, AcceptTombstoneError>>;
  resync(now: Date): Promise<Result<number, ResyncError>>;
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
 * How long an agent's status list index is kept after its last token request.
 * Must exceed the scoped token lifetime (60 s), so a live token is never left
 * without an index. An agent that comes back asks for a new token and is
 * tracked again.
 */
export const TRACKED_AGENT_RETENTION_MS = 5 * 60_000;

interface ResolvedIssuer {
  readonly didDocument: DidWebDocument;
  readonly publicKey: Uint8Array;
}

/**
 * Resolves the revocation service's own DID document and caches it. Tombstones
 * arrive on an unauthenticated endpoint, so an unverified one is worthless:
 * without this check anyone who can reach the vault could revoke any agent.
 *
 * `refresh` re-resolves after the key may have rotated (the revocation
 * service's key changes when its seed does, ADR 0012). Trust is unchanged: the
 * key still comes only from the issuer's own did:web URL. Rate-limited, see
 * above; the tombstone and status list paths share the limit.
 */
function createIssuerResolver(params: {
  readonly issuerDid: string;
  readonly fetchImpl: typeof fetch;
  readonly timeoutMs: number;
}) {
  let cached: ResolvedIssuer | null = null;
  let lastResolvedAt: number | null = null;

  async function fetchIssuer(now: Date): Promise<Result<ResolvedIssuer, IssuerError>> {
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
      cached = { didDocument, publicKey: decodeBase58(multibase.slice(1)).slice(2) };
      return ok(cached);
    } catch (error) {
      return err({ code: "UNVERIFIABLE_ISSUER", reason: `${url}: ${errorMessage(error)}` });
    }
  }

  return {
    current: async (now: Date): Promise<Result<ResolvedIssuer, IssuerError>> =>
      cached ? ok(cached) : fetchIssuer(now),

    /** A freshly resolved issuer, or null if rate-limited or resolution failed. */
    async refresh(now: Date): Promise<ResolvedIssuer | null> {
      if (lastResolvedAt !== null && now.getTime() - lastResolvedAt < KEY_REFRESH_MIN_INTERVAL_MS) {
        return null;
      }
      const resolved = await fetchIssuer(now);
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

/** Where the issuer publishes its status list, derived from its DID alone. */
export function statusListUrlFor(issuerDid: string): string {
  return didWebToResolutionUrl(issuerDid).replace(
    /\/\.well-known\/did\.json$/,
    "/status/revocation",
  );
}

function popcount(bytes: Uint8Array): number {
  let count = 0;
  for (const byte of bytes) {
    let b = byte;
    while (b !== 0) {
      count += b & 1;
      b >>= 1;
    }
  }
  return count;
}

export function createRevocationCache(params: {
  readonly issuerDid: string;
  readonly revocationUrl: string;
  readonly maxStalenessMs: number;
  /**
   * How far apart the revocation service's clock and this one may be. The
   * list's signed `validFrom` is the revocation service's time, so the rule
   * depends on the two clocks agreeing; explicit config, never an accident.
   */
  readonly maxClockSkewMs?: number;
  readonly onRevoked?: (agentDid: string) => Promise<void>;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}): RevocationCache {
  const {
    issuerDid,
    revocationUrl,
    maxStalenessMs,
    maxClockSkewMs = 5_000,
    onRevoked,
    fetchImpl = fetch,
    timeoutMs = 2_000,
  } = params;

  const expectedListUrl = statusListUrlFor(issuerDid);
  // The same rule decides whether a list is acceptable and whether the view is
  // stale, so a list is never accepted only to be stale on arrival.
  const staleAfterMs = maxStalenessMs + maxClockSkewMs;

  /** Agents revoked by a pushed tombstone, or found revoked by a resync. */
  const revokedDids = new Set<string>();
  /** Union of every status list applied. Bits are only ever added. */
  let bits: Uint8Array | null = null;
  /** Agents that asked for a token recently, and which bit is theirs. */
  const tracked = new Map<string, { readonly index: number; readonly seenAt: number }>();
  let freshAsOf: Date | null = null;
  const resolveIssuer = createIssuerResolver({ issuerDid, fetchImpl, timeoutMs });

  function bitSet(index: number): boolean {
    if (bits === null) return false;
    // Past the end of the list means no revocation was published for it as of
    // the list's `validFrom`: revoked indexes are inside the list by
    // construction (the list is sized to the highest revoked one).
    const read = isBitSet(bits, index);
    return read.ok && read.value;
  }

  async function applyTombstone(
    tombstone: string,
    now: Date,
  ): Promise<Result<string, AcceptTombstoneError>> {
    const issuer = await resolveIssuer.current(now);
    if (!issuer.ok) return issuer;

    let verified = verifyRevocationTombstone({ tombstone, publicKey: issuer.value.publicKey });
    if (!verified.ok) {
      // The issuer may have rotated its key since it was cached: re-resolve
      // once and retry before rejecting.
      const refreshed = await resolveIssuer.refresh(now);
      if (refreshed) {
        verified = verifyRevocationTombstone({ tombstone, publicKey: refreshed.publicKey });
      }
    }
    if (!verified.ok) {
      return err({ code: "INVALID_TOMBSTONE", reason: verified.error.code });
    }

    const { agentDid } = verified.value;
    const isNew = !revokedDids.has(agentDid);
    revokedDids.add(agentDid);
    // A pushed tombstone does not refresh the view: it is signed but replayable,
    // and freshness must only come from a list's signed `validFrom`.
    // Fan out to the tool adapters only the first time, so a re-broadcast
    // does not re-hit every connector.
    if (isNew && onRevoked) await onRevoked(agentDid);
    return ok(agentDid);
  }

  async function verifyList(
    credential: SignedCredential,
    now: Date,
  ): Promise<Result<{ list: Uint8Array; validFrom: Date }, ResyncError>> {
    const issuer = await resolveIssuer.current(now);
    if (!issuer.ok) return issuer;

    let verified = await verifyCredential({ credential, didDocument: issuer.value.didDocument });
    if (!verified.ok) {
      // Same key-rotation allowance as for a tombstone.
      const refreshed = await resolveIssuer.refresh(now);
      if (refreshed) {
        verified = await verifyCredential({ credential, didDocument: refreshed.didDocument });
      }
    }
    if (!verified.ok) {
      return err({ code: "INVALID_STATUS_LIST", reason: `signature: ${verified.error.code}` });
    }

    const invalid = (reason: string) => err({ code: "INVALID_STATUS_LIST" as const, reason });
    if (credential.issuer !== issuerDid)
      return invalid("issuer is not the trusted revocation service");
    if (credential.id !== expectedListUrl) return invalid("credential id is not the trusted list");
    if (
      !Array.isArray(credential.type) ||
      !credential.type.includes(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE)
    ) {
      return invalid("not a Bitstring Status List credential");
    }
    const subject = credential.credentialSubject as {
      type?: unknown;
      statusPurpose?: unknown;
      encodedList?: unknown;
    };
    if (subject.type !== BITSTRING_STATUS_LIST_TYPE) return invalid("subject is not a status list");
    if (subject.statusPurpose !== "revocation") return invalid("status purpose is not revocation");
    if (typeof subject.encodedList !== "string") return invalid("missing encodedList");

    const validFrom = new Date(credential.validFrom);
    if (Number.isNaN(validFrom.getTime())) return invalid("validFrom is not a date");
    const ageMs = now.getTime() - validFrom.getTime();
    if (ageMs < -maxClockSkewMs) {
      return err({
        code: "STATUS_LIST_OUT_OF_BOUNDS",
        reason: `validFrom is ${Math.round(-ageMs / 1000)} s ahead of this clock; check the services' clocks`,
      });
    }
    if (ageMs > staleAfterMs) {
      return err({
        code: "STATUS_LIST_OUT_OF_BOUNDS",
        reason: `validFrom is ${Math.round(ageMs / 1000)} s old, past the staleness bound; check the services' clocks`,
      });
    }

    const decoded = decodeStatusList(subject.encodedList);
    if (!decoded.ok) return invalid(`encodedList: ${decoded.error.code}`);
    return ok({ list: decoded.value, validFrom });
  }

  return {
    verdict(agentDid) {
      if (revokedDids.has(agentDid)) return "revoked";
      const entry = tracked.get(agentDid);
      if (entry === undefined) return "unknown";
      return bitSet(entry.index) ? "revoked" : "ok";
    },

    trackAgent(agentDid, credentialStatus, now) {
      const invalid = (reason: string) =>
        err({ code: "INVALID_CREDENTIAL_STATUS" as const, reason });
      if (credentialStatus === null || typeof credentialStatus !== "object") {
        return invalid("credentialStatus is missing");
      }
      const status = credentialStatus as {
        type?: unknown;
        statusPurpose?: unknown;
        statusListCredential?: unknown;
        statusListIndex?: unknown;
      };
      if (status.type !== BITSTRING_STATUS_LIST_ENTRY_TYPE)
        return invalid("not a status list entry");
      if (status.statusPurpose !== "revocation") return invalid("status purpose is not revocation");
      if (status.statusListCredential !== expectedListUrl) {
        return invalid("entry points at a list this vault does not trust");
      }
      // A string of decimal digits, per the spec. Anything else is malformed,
      // never read as "not revoked".
      if (
        typeof status.statusListIndex !== "string" ||
        !/^(0|[1-9][0-9]{0,15})$/.test(status.statusListIndex)
      ) {
        return invalid("statusListIndex is not a non-negative integer");
      }
      const statusListIndex = Number(status.statusListIndex);
      // Re-inserting moves the agent to the back, so the oldest entries are
      // always at the front and pruning stops at the first one still live.
      tracked.delete(agentDid);
      tracked.set(agentDid, { index: statusListIndex, seenAt: now.getTime() });
      for (const [did, entry] of tracked) {
        if (now.getTime() - entry.seenAt <= TRACKED_AGENT_RETENTION_MS) break;
        tracked.delete(did);
      }
      return ok(undefined);
    },

    isStale(now) {
      if (freshAsOf === null) return true;
      return now.getTime() - freshAsOf.getTime() > staleAfterMs;
    },

    status(now) {
      return {
        revokedCount: Math.max(revokedDids.size, bits === null ? 0 : popcount(bits)),
        freshAsOf: freshAsOf?.toISOString() ?? null,
        stale: freshAsOf === null || now.getTime() - freshAsOf.getTime() > staleAfterMs,
      };
    },

    acceptTombstone: (tombstone, now) => applyTombstone(tombstone, now),

    async resync(now) {
      const url = `${revocationUrl.replace(/\/$/, "")}/status/revocation`;
      let credential: SignedCredential;
      try {
        const response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
        if (!response.ok) {
          return err({ code: "UNVERIFIABLE_ISSUER", reason: `${url}: HTTP ${response.status}` });
        }
        credential = (await response.json()) as SignedCredential;
      } catch (error) {
        return err({ code: "UNVERIFIABLE_ISSUER", reason: `${url}: ${errorMessage(error)}` });
      }
      if (credential === null || typeof credential !== "object") {
        return err({ code: "INVALID_STATUS_LIST", reason: `${url}: malformed resync payload` });
      }

      const verified = await verifyList(credential, now);
      if (!verified.ok) return verified;
      const { list, validFrom } = verified.value;

      // Revocation is permanent, so a list can only add: OR it in, never replace.
      // A shorter or older list therefore cannot un-revoke anything.
      const merged = new Uint8Array(Math.max(list.length, bits?.length ?? 0));
      if (bits !== null) merged.set(bits);
      for (let i = 0; i < list.length; i += 1) merged[i] = (merged[i] ?? 0) | (list[i] ?? 0);
      bits = merged;

      // Tell the connectors about agents the list newly shows as revoked. Only
      // agents with a live token are tracked, and those are the ones with
      // anything to cut off.
      for (const [did, entry] of tracked) {
        if (revokedDids.has(did) || !bitSet(entry.index)) continue;
        revokedDids.add(did);
        if (onRevoked) await onRevoked(did);
      }

      // Freshness is the list's own signed time, capped at now, and never moves back.
      const asOf = validFrom.getTime() > now.getTime() ? now : validFrom;
      if (freshAsOf === null || asOf.getTime() > freshAsOf.getTime()) freshAsOf = asOf;
      return ok(popcount(list));
    },
  };
}

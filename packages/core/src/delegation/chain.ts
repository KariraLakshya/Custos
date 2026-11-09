import { verify } from "../crypto/ed25519.js";
import { multibaseToPublicKey, type DidWebDocument } from "../did/did-web.js";
import { parseTimestamp } from "../federation/trust-anchor.js";
import { isBoundRequest, type BoundRequest } from "../proof/possession.js";
import { err, ok, type Result } from "../result.js";
import { verifyCredential, type SignedCredential } from "../vc/credential.js";
import {
  HAND_OFF_TYPE,
  handOffHash,
  isDelegatedGrantList,
  type DelegatedGrant,
  type HandOffClaims,
} from "./hand-off.js";

/**
 * What an agent acting for another presents (ADR 0020 §2): the hand-offs from
 * the first delegator to the requester, in order, and for each one the
 * delegating agent's own credential, so its key and status-list entry are
 * known without a fetch.
 */
export interface DelegationChain {
  readonly handOffs: readonly string[];
  readonly credentials: readonly SignedCredential[];
}

/** Explicit configuration, validated at boot; never bypassed. */
export interface DelegationLimits {
  /** Most hand-offs in one chain (ADR 0020: default 3). */
  readonly maxLinks: number;
  /** Longest a hand-off may live, `exp − iat` (default 3600). */
  readonly maxLifetimeSeconds: number;
  /** Most bytes in the hand-offs and credentials together (default 16 KiB). */
  readonly maxBytes: number;
  /** How far ahead of `now` an `iat` or `validFrom` may be. */
  readonly maxClockSkewSeconds: number;
}

/** A chain that verified. Every DID in it was proven by a signature. */
export interface VerifiedDelegation {
  /** The first delegator: the agent whose own grant is the root (ADR 0020 §1). */
  readonly rootDid: string;
  /** From the first delegator to the requester. */
  readonly dids: readonly string[];
  /** Each delegator, with its credential's status entry for revocation tracking. */
  readonly delegators: readonly { readonly did: string; readonly credentialStatus: unknown }[];
  /** The earliest of every hand-off's `exp` and every delegator credential's `validUntil`. */
  readonly expiresAt: Date;
}

/** `link` is the 0-based position of the hand-off the refusal is about. */
export type DelegationChainError =
  | { readonly code: "INVALID_LIMITS" }
  | { readonly code: "MALFORMED_CHAIN"; readonly reason: string }
  | { readonly code: "TOO_LARGE" }
  | { readonly code: "TOO_MANY_LINKS" }
  | { readonly code: "CREDENTIAL_INVALID"; readonly link: number; readonly reason: string }
  | { readonly code: "SIGNATURE_INVALID"; readonly link: number }
  | { readonly code: "WRONG_TYPE"; readonly link: number }
  | { readonly code: "BROKEN_LINK"; readonly link: number; readonly reason: string }
  | { readonly code: "NOT_YET_VALID"; readonly link: number }
  | { readonly code: "EXPIRED"; readonly link: number }
  | { readonly code: "WIDENED"; readonly link: number; readonly reason: string }
  | { readonly code: "WRONG_HOLDER" }
  | { readonly code: "NOT_COVERED" };

const MAX_DID_LENGTH = 512;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPositiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function isDid(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_DID_LENGTH;
}

function isHandOffClaims(value: unknown): value is HandOffClaims {
  if (!isRecord(value)) return false;
  return (
    typeof value.typ === "string" &&
    isDid(value.iss) &&
    isDid(value.sub) &&
    isDelegatedGrantList(value.grants) &&
    Number.isSafeInteger(value.depth) &&
    (value.depth as number) >= 0 &&
    (value.prev === null || typeof value.prev === "string") &&
    Number.isSafeInteger(value.iat) &&
    Number.isSafeInteger(value.exp) &&
    typeof value.jti === "string"
  );
}

/** Every tool and action in `child` is in `parent`. */
function isWithin(child: readonly DelegatedGrant[], parent: readonly DelegatedGrant[]): boolean {
  return child.every((grant) => {
    const held = parent.find((candidate) => candidate.tool === grant.tool);
    return held !== undefined && grant.actions.every((action) => held.actions.includes(action));
  });
}

interface Delegator {
  readonly did: string;
  readonly key: Uint8Array;
  readonly credentialStatus: unknown;
  readonly validUntil: Date | undefined;
}

/**
 * A delegator's credential: issued by the pinned identity issuer, signature
 * valid under its document, in its validity period, and naming an agent and
 * its key. Same checks as the vault makes of a requester's credential.
 */
async function verifyDelegator(
  credential: unknown,
  link: number,
  issuer: { readonly did: string; readonly document: DidWebDocument },
  now: Date,
  maxClockSkewSeconds: number,
): Promise<Result<Delegator, DelegationChainError>> {
  const invalid = (reason: string): Result<never, DelegationChainError> =>
    err({ code: "CREDENTIAL_INVALID", link, reason });

  if (!isRecord(credential)) return invalid("not an object");
  if (credential.issuer !== issuer.did) return invalid("UNTRUSTED_ISSUER");
  const verified = await verifyCredential({
    credential: credential as unknown as SignedCredential,
    didDocument: issuer.document,
  });
  if (!verified.ok) return invalid(verified.error.code);

  const subject = credential.credentialSubject;
  if (!isRecord(subject) || !isDid(subject.id)) return invalid("MISSING_SUBJECT");
  if (typeof subject.publicKeyMultibase !== "string") return invalid("MISSING_AGENT_KEY");
  const key = multibaseToPublicKey(subject.publicKeyMultibase);
  if (!key.ok) return invalid("MISSING_AGENT_KEY");

  const validFrom = parseTimestamp(credential.validFrom);
  if (validFrom === undefined) return invalid("validFrom is not a timestamp");
  if (validFrom.getTime() - now.getTime() > maxClockSkewSeconds * 1000) {
    return invalid("NOT_YET_VALID");
  }
  let validUntil: Date | undefined;
  if (credential.validUntil !== undefined) {
    validUntil = parseTimestamp(credential.validUntil);
    if (validUntil === undefined) return invalid("validUntil is not a timestamp");
    if (now.getTime() >= validUntil.getTime()) return invalid("EXPIRED");
  }
  return ok({
    did: subject.id,
    key: key.value,
    credentialStatus: credential.credentialStatus,
    validUntil,
  });
}

/** Signature first, under the delegator's key; nothing in the claims is read before it. */
function openHandOff(
  handOff: string,
  key: Uint8Array,
  link: number,
): Result<HandOffClaims, DelegationChainError> {
  const parts = handOff.split(".");
  if (parts.length !== 2) {
    return err({ code: "MALFORMED_CHAIN", reason: `hand-off ${link} is not two parts` });
  }
  const [encodedClaims, encodedSignature] = parts as [string, string];
  if (
    !verify(Buffer.from(encodedSignature, "base64url"), Buffer.from(encodedClaims, "utf8"), key)
  ) {
    return err({ code: "SIGNATURE_INVALID", link });
  }
  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8"));
  } catch {
    return err({ code: "MALFORMED_CHAIN", reason: `hand-off ${link} is not JSON` });
  }
  if (!isHandOffClaims(claims)) {
    return err({ code: "MALFORMED_CHAIN", reason: `hand-off ${link} is missing fields` });
  }
  return ok(claims);
}

/**
 * Checks a delegation chain entirely locally (ADR 0020 §3): no network call,
 * no database, no clock read. `chain` is attacker controlled, so it is
 * `unknown` and checked from the outside in; every refusal is a value.
 *
 * Checked: size before parsing; each delegator's credential against the
 * pinned issuer; each hand-off's signature under that credential's key; the
 * links bound both ways (`iss` is the previous `sub`, `prev` the previous
 * hash, the first `prev` null) so a hand-off cannot be spliced from another
 * chain; nothing widens (tools and actions, `exp`, `depth`) and no hand-off
 * outlives `maxLifetimeSeconds`; the last hand-off names the requester, so a
 * prefix of someone else's chain is useless; and it covers this request.
 *
 * Not checked here: that the first delegator holds a grant for the tool. That
 * is the vault's own table (ADR 0020 §4), looked up with `rootDid` after this
 * returns. The requester's own credential and proof of possession are the
 * caller's, checked before this runs.
 */
export async function verifyDelegationChain(params: {
  readonly chain: unknown;
  /** Proven by the caller (the requester's proof of possession). */
  readonly requesterDid: string;
  readonly request: BoundRequest;
  /** The pinned identity issuer and its already-resolved DID document. */
  readonly issuer: { readonly did: string; readonly document: DidWebDocument };
  /** The time to judge validity at: now on the hot path, the entry's time for an auditor. */
  readonly now: Date;
  readonly limits: DelegationLimits;
}): Promise<Result<VerifiedDelegation, DelegationChainError>> {
  const { chain, requesterDid, request, issuer, now, limits } = params;

  if (
    !isPositiveInteger(limits.maxLinks) ||
    !isPositiveInteger(limits.maxLifetimeSeconds) ||
    !isPositiveInteger(limits.maxBytes) ||
    !Number.isSafeInteger(limits.maxClockSkewSeconds) ||
    limits.maxClockSkewSeconds < 0
  ) {
    return err({ code: "INVALID_LIMITS" });
  }
  if (!isBoundRequest(request)) return err({ code: "MALFORMED_CHAIN", reason: "bad request" });

  // 1. Shape and size, before any parsing of what is inside.
  if (!isRecord(chain)) return err({ code: "MALFORMED_CHAIN", reason: "not an object" });
  const { handOffs, credentials } = chain;
  if (!Array.isArray(handOffs) || !Array.isArray(credentials)) {
    return err({ code: "MALFORMED_CHAIN", reason: "handOffs and credentials must be arrays" });
  }
  if (handOffs.length === 0) return err({ code: "MALFORMED_CHAIN", reason: "no hand-offs" });
  if (handOffs.length > limits.maxLinks) return err({ code: "TOO_MANY_LINKS" });
  if (credentials.length !== handOffs.length) {
    return err({ code: "MALFORMED_CHAIN", reason: "one credential per hand-off" });
  }
  if (!handOffs.every((handOff): handOff is string => typeof handOff === "string")) {
    return err({ code: "MALFORMED_CHAIN", reason: "hand-offs must be strings" });
  }
  let size = 0;
  for (const handOff of handOffs) size += handOff.length;
  if (size > limits.maxBytes) return err({ code: "TOO_LARGE" });
  try {
    size += JSON.stringify(credentials).length;
  } catch {
    return err({ code: "MALFORMED_CHAIN", reason: "credentials are not serialisable" });
  }
  if (size > limits.maxBytes) return err({ code: "TOO_LARGE" });

  // 2. Link by link, from the first delegator down.
  const verifiedClaims: HandOffClaims[] = [];
  const delegators: { did: string; credentialStatus: unknown }[] = [];
  let expiresAtMs = Number.POSITIVE_INFINITY;
  const nowSeconds = Math.floor(now.getTime() / 1000);

  for (let link = 0; link < handOffs.length; link++) {
    const delegator = await verifyDelegator(
      credentials[link],
      link,
      issuer,
      now,
      limits.maxClockSkewSeconds,
    );
    if (!delegator.ok) return delegator;
    if (delegator.value.validUntil !== undefined) {
      expiresAtMs = Math.min(expiresAtMs, delegator.value.validUntil.getTime());
    }

    const opened = openHandOff(handOffs[link]!, delegator.value.key, link);
    if (!opened.ok) return opened;
    const claims = opened.value;
    if (claims.typ !== HAND_OFF_TYPE) return err({ code: "WRONG_TYPE", link });

    // Bound both ways (Delegate SD-JWT §8.1): signed by the agent the
    // credential names, extending exactly the previous signed hand-off.
    if (claims.iss !== delegator.value.did) {
      return err({ code: "BROKEN_LINK", link, reason: "not signed by the agent it names" });
    }
    const parent = verifiedClaims[link - 1];
    if (parent === undefined) {
      if (claims.prev !== null) {
        return err({ code: "BROKEN_LINK", link, reason: "first hand-off names a previous one" });
      }
    } else {
      if (claims.iss !== parent.sub) {
        return err({ code: "BROKEN_LINK", link, reason: "issuer is not the previous delegate" });
      }
      if (claims.prev !== handOffHash(handOffs[link - 1]!)) {
        return err({ code: "BROKEN_LINK", link, reason: "does not extend the previous hand-off" });
      }
    }

    // Time.
    if (claims.exp <= claims.iat) {
      return err({ code: "MALFORMED_CHAIN", reason: `hand-off ${link} ends before it starts` });
    }
    if (claims.iat - nowSeconds > limits.maxClockSkewSeconds) {
      return err({ code: "NOT_YET_VALID", link });
    }
    if (nowSeconds >= claims.exp) return err({ code: "EXPIRED", link });
    if (claims.exp - claims.iat > limits.maxLifetimeSeconds) {
      return err({ code: "WIDENED", link, reason: "lives longer than the limit" });
    }

    // Never widens. The first hand-off's tools are checked against the root
    // grant by the caller; below it, each is checked against its parent.
    if (parent === undefined) {
      if (claims.depth > limits.maxLinks - 1) {
        return err({ code: "WIDENED", link, reason: "allows more links than the limit" });
      }
    } else {
      if (claims.exp > parent.exp) {
        return err({ code: "WIDENED", link, reason: "outlives the previous hand-off" });
      }
      if (claims.depth >= parent.depth) {
        return err({ code: "WIDENED", link, reason: "allows as many links as the previous one" });
      }
      if (!isWithin(claims.grants, parent.grants)) {
        return err({ code: "WIDENED", link, reason: "grants more than the previous hand-off" });
      }
    }

    verifiedClaims.push(claims);
    delegators.push({
      did: delegator.value.did,
      credentialStatus: delegator.value.credentialStatus,
    });
    expiresAtMs = Math.min(expiresAtMs, claims.exp * 1000);
  }

  // 3. Ends at the requester, and covers this request.
  const last = verifiedClaims[verifiedClaims.length - 1]!;
  if (last.sub !== requesterDid) return err({ code: "WRONG_HOLDER" });
  if (!isWithin([{ tool: request.tool, actions: [request.action] }], last.grants)) {
    return err({ code: "NOT_COVERED" });
  }

  return ok({
    rootDid: verifiedClaims[0]!.iss,
    dids: [...verifiedClaims.map((claims) => claims.iss), last.sub],
    delegators,
    expiresAt: new Date(expiresAtMs),
  });
}

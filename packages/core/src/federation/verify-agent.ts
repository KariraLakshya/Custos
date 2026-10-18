import { multibaseToPublicKey } from "../did/did-web.js";
import {
  FOREIGN_CALL_PROOF_TYPE,
  proofReplayExpiresAtMs,
  verifyPossessionProof,
} from "../proof/possession.js";
import type { VerifyPossessionProofError } from "../proof/possession.js";
import { err, ok, type Result } from "../result.js";
import { BITSTRING_STATUS_LIST_ENTRY_TYPE, isRevoked } from "../status/bitstring-status-list.js";
import { verifyCredential, type SignedCredential } from "../vc/credential.js";
import type { VerifiedForeignStatusList } from "./status-view.js";
import {
  isUsableAnchorWindow,
  parseTimestamp,
  pinnedDidDocument,
  selectTrustAnchor,
  type TrustAnchor,
} from "./trust-anchor.js";

/**
 * Remembers proof ids so a captured proof cannot be replayed. Same shape as the
 * vault's `ReplayCache`, but a result may come back asynchronously so a shared
 * store (Redis) can back it when more than one verifier runs.
 */
export interface ForeignReplayGuard {
  record(key: string, expiresAtMs: number, nowMs: number): ReplayVerdict | Promise<ReplayVerdict>;
}
export type ReplayVerdict = "fresh" | "replayed" | "full";

export type ForeignDenial =
  | { readonly code: "MALFORMED_INPUT"; readonly reason: string }
  | { readonly code: "NO_TRUST_ANCHOR" }
  | { readonly code: "ANCHOR_DISABLED"; readonly domain: string }
  | { readonly code: "ANCHOR_INVALID"; readonly domain: string }
  | { readonly code: "CREDENTIAL_SIGNATURE_INVALID"; readonly reason: string }
  | { readonly code: "CREDENTIAL_SUBJECT_INVALID"; readonly reason: string }
  | { readonly code: "CREDENTIAL_TIME_INVALID"; readonly reason: string }
  | { readonly code: "CREDENTIAL_NOT_YET_VALID" }
  | { readonly code: "CREDENTIAL_EXPIRED" }
  | { readonly code: "PROOF_REJECTED"; readonly reason: VerifyPossessionProofError["code"] }
  | { readonly code: "PROOF_REPLAYED" }
  | { readonly code: "REPLAY_GUARD_FULL" }
  | { readonly code: "STATUS_ENTRY_INVALID"; readonly reason: string }
  | { readonly code: "STATUS_UNAVAILABLE" }
  | { readonly code: "STATUS_VIEW_MISMATCH" }
  | { readonly code: "AGENT_REVOKED" }
  | { readonly code: "STATUS_STALE" };

export interface ForeignAgent {
  readonly agentDid: string;
  /** The anchor's label, for logs and audit. */
  readonly domain: string;
  readonly issuerDid: string;
  readonly credentialId: string;
  readonly statusListIndex: number;
  /** The signed time of the list this decision rests on. */
  readonly statusAsOf: Date;
}

// A real agent credential is about 1.5 KiB.
const MAX_CREDENTIAL_BYTES = 16_384;
const DECIMAL_INDEX = /^\d{1,15}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function malformed(reason: string): Result<never, ForeignDenial> {
  return err({ code: "MALFORMED_INPUT", reason });
}

/**
 * Decides, with no network call and no knowledge of the issuing organisation
 * beyond the pinned `anchors`, whether a foreign agent's call is allowed
 * (ADR 0014 decisions 1 and 2). Both `credential` and `proof` are attacker
 * controlled, so they are `unknown` and checked from the outside in; the
 * issuer is matched exactly against the pinned anchors before the (expensive)
 * signature is checked, and nothing a credential says is believed until its
 * signature has verified under the pinned key.
 *
 * Every step is a named denial; this function does not throw on bad input.
 */
export async function verifyForeignAgent(params: {
  readonly credential: unknown;
  readonly proof: unknown;
  readonly anchors: readonly TrustAnchor[];
  /** The current verified status view for an anchor, if B has one. */
  readonly statusViewFor: (anchor: TrustAnchor) => VerifiedForeignStatusList | undefined;
  /** This receiver's own identifier: the proof must be addressed to it. */
  readonly audience: string;
  readonly replay: ForeignReplayGuard;
  readonly now: Date;
  /** Explicit configuration, no default: how far a proof's `iat` may be from now. */
  readonly maxProofSkewSeconds: number;
  /** Explicit configuration, no default: how far ahead the issuer's clock may be. */
  readonly maxClockSkewSeconds: number;
}): Promise<Result<ForeignAgent, ForeignDenial>> {
  const { credential, proof, anchors, audience, replay, now } = params;

  if (!isRecord(credential)) return malformed("credential is not an object");
  if (typeof proof !== "string") return malformed("proof is not a string");
  let size: number;
  try {
    size = JSON.stringify(credential).length;
  } catch {
    return malformed("credential is not serialisable");
  }
  if (size > MAX_CREDENTIAL_BYTES) return malformed("credential exceeds maximum size");

  // 1. Who issued it: exact match against the pinned anchors, before any crypto.
  const anchor = selectTrustAnchor(anchors, credential.issuer);
  if (anchor === undefined) return err({ code: "NO_TRUST_ANCHOR" });
  if (!anchor.enabled) return err({ code: "ANCHOR_DISABLED", domain: anchor.domain });
  if (!isUsableAnchorWindow(anchor)) return err({ code: "ANCHOR_INVALID", domain: anchor.domain });

  // 2. The signature, under the pinned key. Everything read below is covered by it.
  const verified = await verifyCredential({
    credential: credential as unknown as SignedCredential,
    didDocument: pinnedDidDocument(anchor.credentialIssuerDid, anchor.credentialIssuerPublicKey),
  });
  if (!verified.ok) {
    return err({ code: "CREDENTIAL_SIGNATURE_INVALID", reason: verified.error.code });
  }

  // 3. Who it names, and the key it embeds.
  const subject = credential.credentialSubject;
  if (!isRecord(subject)) return err({ code: "CREDENTIAL_SUBJECT_INVALID", reason: "no subject" });
  const { id: agentDid, publicKeyMultibase } = subject;
  if (typeof agentDid !== "string" || agentDid === "") {
    return err({ code: "CREDENTIAL_SUBJECT_INVALID", reason: "no subject id" });
  }
  if (typeof publicKeyMultibase !== "string") {
    return err({ code: "CREDENTIAL_SUBJECT_INVALID", reason: "no embedded key" });
  }
  // An organisation may only vouch for agents in its own namespace: with two
  // trusted anchors, one must not be able to sign a credential that names the
  // other's agent. (Custos agent DIDs are `<issuer DID>:agents:<id>`.)
  if (!agentDid.startsWith(`${anchor.credentialIssuerDid}:`)) {
    return err({
      code: "CREDENTIAL_SUBJECT_INVALID",
      reason: "agent is not in the issuer's namespace",
    });
  }
  const agentKey = multibaseToPublicKey(publicKeyMultibase);
  if (!agentKey.ok) {
    return err({ code: "CREDENTIAL_SUBJECT_INVALID", reason: "embedded key is unusable" });
  }

  // 4. Its own validity period. An absent `validUntil` is allowed (agent
  // credentials do not carry one today); a present but unreadable one is not.
  const validFrom = parseTimestamp(credential.validFrom);
  if (validFrom === undefined) {
    return err({ code: "CREDENTIAL_TIME_INVALID", reason: "validFrom is not a timestamp" });
  }
  if (validFrom.getTime() - now.getTime() > params.maxClockSkewSeconds * 1000) {
    return err({ code: "CREDENTIAL_NOT_YET_VALID" });
  }
  if (credential.validUntil !== undefined) {
    const validUntil = parseTimestamp(credential.validUntil);
    if (validUntil === undefined) {
      return err({ code: "CREDENTIAL_TIME_INVALID", reason: "validUntil is not a timestamp" });
    }
    if (now.getTime() >= validUntil.getTime()) return err({ code: "CREDENTIAL_EXPIRED" });
  }

  // 5. Possession: this caller holds the embedded key, addressed to us, fresh.
  const claims = verifyPossessionProof({
    proof,
    publicKey: agentKey.value,
    expectedType: FOREIGN_CALL_PROOF_TYPE,
    expectedAudience: audience,
    now,
    maxSkewSeconds: params.maxProofSkewSeconds,
  });
  if (!claims.ok) return err({ code: "PROOF_REJECTED", reason: claims.error.code });

  // 6. Replay. Recorded only now, after the proof's signature verified, so an
  // unsigned proof cannot fill the guard; keyed by agent so ids cannot collide
  // across agents and issuers.
  const verdict = await replay.record(
    `${anchor.credentialIssuerDid}|${agentDid}|${claims.value.jti}`,
    proofReplayExpiresAtMs(claims.value.iat, params.maxProofSkewSeconds),
    now.getTime(),
  );
  if (verdict === "replayed") return err({ code: "PROOF_REPLAYED" });
  if (verdict === "full") return err({ code: "REPLAY_GUARD_FULL" });

  // 7. Where its revocation bit lives. A foreign agent with no status entry
  // cannot be checked for revocation, so it is refused.
  const status = credential.credentialStatus;
  if (!isRecord(status)) return err({ code: "STATUS_ENTRY_INVALID", reason: "missing" });
  if (status.type !== BITSTRING_STATUS_LIST_ENTRY_TYPE || status.statusPurpose !== "revocation") {
    return err({ code: "STATUS_ENTRY_INVALID", reason: "not a revocation entry" });
  }
  if (status.statusListCredential !== anchor.statusListId) {
    return err({
      code: "STATUS_ENTRY_INVALID",
      reason: "points at a list that is not the anchor's",
    });
  }
  if (typeof status.statusListIndex !== "string" || !DECIMAL_INDEX.test(status.statusListIndex)) {
    return err({ code: "STATUS_ENTRY_INVALID", reason: "index is not a decimal number" });
  }
  const statusListIndex = Number(status.statusListIndex);

  // 8. Revoked is checked before stale: a revocation is never cleared, so a
  // revoked agent is answered as revoked even when the list has aged out.
  const view = params.statusViewFor(anchor);
  if (view === undefined) return err({ code: "STATUS_UNAVAILABLE" });
  // The view must have been verified for this anchor's list, not another's.
  if (view.statusListId !== anchor.statusListId) return err({ code: "STATUS_VIEW_MISMATCH" });
  const bit = isRevoked(view.list, statusListIndex);
  // An index past the end of the list means "not revoked" (ADR 0013): the list
  // is sized to its highest revoked index, so every revoked index is inside it.
  if (bit.ok && bit.value) return err({ code: "AGENT_REVOKED" });
  if (now.getTime() >= view.notAfter.getTime()) return err({ code: "STATUS_STALE" });

  return ok({
    agentDid,
    domain: anchor.domain,
    issuerDid: anchor.credentialIssuerDid,
    credentialId: typeof credential.id === "string" ? credential.id : "",
    statusListIndex,
    statusAsOf: view.validFrom,
  });
}

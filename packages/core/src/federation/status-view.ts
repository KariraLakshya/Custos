import { err, ok, type Result } from "../result.js";
import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_TYPE,
  decodeStatusList,
} from "../status/bitstring-status-list.js";
import { verifyCredential, type SignedCredential } from "../vc/credential.js";
import {
  isUsableAnchorWindow,
  parseTimestamp,
  pinnedDidDocument,
  type TrustAnchor,
} from "./trust-anchor.js";

declare const verifiedBrand: unique symbol;

/**
 * A foreign status list that passed `verifyForeignStatusList`, and the only
 * thing `applyStatusList` and `verifyForeignAgent` accept: an unverified list
 * cannot be merged or consulted by mistake.
 */
export interface VerifiedForeignStatusList {
  readonly [verifiedBrand]: true;
  /** The list this was verified as: an anchor's `statusListId`. */
  readonly statusListId: string;
  readonly list: Uint8Array;
  /** The issuer's signed time. Freshness comes from here, never from receipt. */
  readonly validFrom: Date;
  /** After this the list is not acted on: `min(validUntil, validFrom + maxStatusAge)`. */
  readonly notAfter: Date;
}

export type ForeignStatusListError =
  | { readonly code: "ANCHOR_INVALID"; readonly reason: string }
  | { readonly code: "LIST_MALFORMED"; readonly reason: string }
  | { readonly code: "LIST_WRONG_ISSUER" }
  | { readonly code: "LIST_WRONG_ID" }
  | { readonly code: "LIST_SIGNATURE_INVALID"; readonly reason: string }
  | { readonly code: "LIST_NOT_A_REVOCATION_LIST" }
  | { readonly code: "LIST_NO_VALID_UNTIL" }
  | { readonly code: "LIST_FUTURE_DATED" }
  | { readonly code: "LIST_STALE" };

// A list is 16 KiB raw at the 131,072-entry minimum and compresses well; this
// leaves room for a very large one while refusing a hostile body early.
const MAX_LIST_CREDENTIAL_BYTES = 1_048_576;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function malformed(reason: string): Result<never, ForeignStatusListError> {
  return err({ code: "LIST_MALFORMED", reason });
}

/**
 * Verifies a published status list against the anchor's pinned status key and
 * identity (ADR 0014). `credential` arrives from a file host that is not
 * trusted, so it is `unknown` and checked from the outside in: size, shape,
 * issuer and id (cheap, before the signature), then the signature, then the
 * signed times. Local only; no step reaches the list's publisher.
 */
export async function verifyForeignStatusList(params: {
  readonly credential: unknown;
  readonly anchor: TrustAnchor;
  readonly now: Date;
  /** Explicit configuration: how far the publisher's clock may be ahead of ours. */
  readonly maxClockSkewSeconds: number;
}): Promise<Result<VerifiedForeignStatusList, ForeignStatusListError>> {
  const { credential, anchor, now, maxClockSkewSeconds } = params;

  if (!isUsableAnchorWindow(anchor)) {
    return err({
      code: "ANCHOR_INVALID",
      reason: "maxStatusAgeSeconds must be a positive integer",
    });
  }
  if (!isRecord(credential)) return malformed("not an object");
  let size: number;
  try {
    size = JSON.stringify(credential).length;
  } catch {
    return malformed("not serialisable");
  }
  if (size > MAX_LIST_CREDENTIAL_BYTES) return malformed("exceeds maximum size");

  if (credential.issuer !== anchor.statusIssuerDid) return err({ code: "LIST_WRONG_ISSUER" });
  if (credential.id !== anchor.statusListId) return err({ code: "LIST_WRONG_ID" });

  const verified = await verifyCredential({
    credential: credential as unknown as SignedCredential,
    didDocument: pinnedDidDocument(anchor.statusIssuerDid, anchor.statusIssuerPublicKey),
  });
  if (!verified.ok) {
    return err({ code: "LIST_SIGNATURE_INVALID", reason: verified.error.code });
  }

  // Past this point every field below is covered by the signature.
  const { type, credentialSubject } = credential;
  if (!Array.isArray(type) || !type.includes(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE)) {
    return err({ code: "LIST_NOT_A_REVOCATION_LIST" });
  }
  if (
    !isRecord(credentialSubject) ||
    credentialSubject.type !== BITSTRING_STATUS_LIST_TYPE ||
    credentialSubject.statusPurpose !== "revocation" ||
    typeof credentialSubject.encodedList !== "string"
  ) {
    return err({ code: "LIST_NOT_A_REVOCATION_LIST" });
  }

  const validFrom = parseTimestamp(credential.validFrom);
  if (validFrom === undefined) return malformed("validFrom is not a timestamp");
  if (credential.validUntil === undefined) return err({ code: "LIST_NO_VALID_UNTIL" });
  const validUntil = parseTimestamp(credential.validUntil);
  if (validUntil === undefined) return malformed("validUntil is not a timestamp");
  if (validUntil.getTime() <= validFrom.getTime())
    return malformed("validUntil is not after validFrom");

  if (validFrom.getTime() - now.getTime() > maxClockSkewSeconds * 1000) {
    return err({ code: "LIST_FUTURE_DATED" });
  }
  const notAfter = new Date(
    Math.min(validUntil.getTime(), validFrom.getTime() + anchor.maxStatusAgeSeconds * 1000),
  );
  if (now.getTime() >= notAfter.getTime()) return err({ code: "LIST_STALE" });

  const decoded = decodeStatusList(credentialSubject.encodedList);
  if (!decoded.ok) return malformed(`encodedList: ${decoded.error.code}`);

  return ok({
    statusListId: anchor.statusListId,
    list: decoded.value,
    validFrom,
    notAfter,
  } as VerifiedForeignStatusList);
}

/**
 * Folds a newly verified list into what B already knows. Revocation is
 * permanent, so the bits are unioned and never cleared: a stale or replayed
 * list can only fail to add. Freshness follows the list with the later signed
 * `validFrom` and never moves backwards, so replaying an old list buys only
 * what is left of its own window.
 */
export function applyStatusList(
  previous: VerifiedForeignStatusList | undefined,
  next: VerifiedForeignStatusList,
): VerifiedForeignStatusList {
  if (previous === undefined) return next;
  // Two different lists must never be merged; a caller doing so has a routing bug.
  if (previous.statusListId !== next.statusListId) {
    throw new Error("applyStatusList: lists belong to different anchors");
  }

  const merged = new Uint8Array(Math.max(previous.list.length, next.list.length));
  for (let i = 0; i < merged.length; i += 1) {
    merged[i] = (previous.list[i] ?? 0) | (next.list[i] ?? 0);
  }
  const newer = next.validFrom.getTime() > previous.validFrom.getTime() ? next : previous;
  return {
    statusListId: next.statusListId,
    list: merged,
    validFrom: newer.validFrom,
    notAfter: newer.notAfter,
  } as VerifiedForeignStatusList;
}

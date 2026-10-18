import type { DidWebDocument } from "../did/did-web.js";
import { publicKeyToMultibase } from "../did/did-web.js";

/**
 * What one organisation (B) is configured to trust about another (A), supplied
 * out of band (ADR 0014 decision 1). Nothing here is ever resolved or fetched
 * during verification: A's keys are pinned, so A's servers can be off.
 */
export interface TrustAnchor {
  /** A label B uses in logs and audit. Never trusted as an identity. */
  readonly domain: string;
  /** Signs A's agent credentials (the identity service). */
  readonly credentialIssuerDid: string;
  readonly credentialIssuerPublicKey: Uint8Array;
  /** Signs A's status list (the revocation identity). A different key. */
  readonly statusIssuerDid: string;
  readonly statusIssuerPublicKey: Uint8Array;
  /**
   * The list's identity: must equal the credential's `statusListCredential`
   * and the list VC's `id`. Not where the list is fetched from.
   */
  readonly statusListId: string;
  /** How old a list may be before B stops acting on it. Required, no default. */
  readonly maxStatusAgeSeconds: number;
  /** B's own switch to distrust the whole domain. */
  readonly enabled: boolean;
}

/** An exact match on the issuer a credential names; nothing fuzzier. */
export function selectTrustAnchor(
  anchors: readonly TrustAnchor[],
  issuer: unknown,
): TrustAnchor | undefined {
  if (typeof issuer !== "string") return undefined;
  return anchors.find((anchor) => anchor.credentialIssuerDid === issuer);
}

/** The anchor's numbers are configuration, but a bad one must fail closed, not open. */
export function isUsableAnchorWindow(anchor: TrustAnchor): boolean {
  return Number.isSafeInteger(anchor.maxStatusAgeSeconds) && anchor.maxStatusAgeSeconds > 0;
}

/**
 * A DID document built from a pinned key, in the shape `buildDidWebDocument`
 * produces (`<did>#<multibase>` as the verification method), so a credential
 * signed by the real issuer verifies and one signed by any other key does not.
 */
export function pinnedDidDocument(did: string, publicKey: Uint8Array): DidWebDocument {
  const publicKeyMultibase = publicKeyToMultibase(publicKey);
  const verificationMethodId = `${did}#${publicKeyMultibase}`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase,
      },
    ],
    assertionMethod: [verificationMethodId],
  };
}

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/**
 * Strict timestamp parsing. `new Date("2026-1")` and friends are accepted by
 * the engine; a security decision about time must not be, so only full ISO 8601
 * with an explicit offset passes. Anything else is `undefined`, which callers
 * treat as a denial, never as "no value".
 */
export function parseTimestamp(value: unknown): Date | undefined {
  if (typeof value !== "string" || !ISO_TIMESTAMP.test(value)) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

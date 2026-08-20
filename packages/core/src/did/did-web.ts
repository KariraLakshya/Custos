import * as base58btc from "base58-universal";

const MULTIBASE_BASE58BTC_PREFIX = "z";
// multicodec ed25519-pub varint header, per the Ed25519VerificationKey2020 spec
const MULTICODEC_ED25519_PUB_HEADER = new Uint8Array([0xed, 0x01]);

/**
 * Encodes a raw 32-byte Ed25519 public key as an Ed25519VerificationKey2020
 * multibase fingerprint. Public-key-only by design: a DID document must be
 * buildable from what a KMS-backed key provider can hand out later, without
 * ever needing the private key.
 */
export function publicKeyToMultibase(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(MULTICODEC_ED25519_PUB_HEADER.length + publicKey.length);
  prefixed.set(MULTICODEC_ED25519_PUB_HEADER, 0);
  prefixed.set(publicKey, MULTICODEC_ED25519_PUB_HEADER.length);
  return MULTIBASE_BASE58BTC_PREFIX + base58btc.encode(prefixed);
}

export interface Ed25519VerificationMethod2020 {
  readonly id: string;
  readonly type: "Ed25519VerificationKey2020";
  readonly controller: string;
  readonly publicKeyMultibase: string;
}

export interface DidWebDocument {
  readonly "@context": readonly [string, string];
  readonly id: string;
  readonly verificationMethod: readonly [Ed25519VerificationMethod2020];
  readonly assertionMethod: readonly [string];
}

/** did:web only supports a bare domain here; per-agent path segments are Phase 1 (agent registry) work. */
export function didWebFromDomain(domain: string): string {
  return `did:web:${domain.replace(":", "%3A")}`;
}

export function buildDidWebDocument(params: {
  readonly domain: string;
  readonly publicKey: Uint8Array;
}): DidWebDocument {
  const did = didWebFromDomain(params.domain);
  const publicKeyMultibase = publicKeyToMultibase(params.publicKey);
  const verificationMethodId = `${did}#${publicKeyMultibase}`;
  const verificationMethod: Ed25519VerificationMethod2020 = {
    id: verificationMethodId,
    type: "Ed25519VerificationKey2020",
    controller: did,
    publicKeyMultibase,
  };
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [verificationMethod],
    assertionMethod: [verificationMethodId],
  };
}

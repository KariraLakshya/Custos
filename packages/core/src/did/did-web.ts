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

/**
 * `assertionMethod` only — this key signs/verifies VCs, nothing else. If a
 * later phase needs `keyAgreement` (e.g. an encrypted channel for vault
 * token handoff, or the Phase 6 cross-org handshake), that is a separate
 * X25519 keypair with its own verification method, never this Ed25519 key
 * reused or converted: EdDSA and X25519 share a curve family but signing
 * and Diffie-Hellman are different algorithms, and reusing key material
 * across them is a known source of cross-protocol attacks, not just a
 * DID-spec labelling convention (the same reasoning behind X.509 Key Usage
 * extensions restricting a cert to one purpose).
 */
export interface DidWebDocument {
  readonly "@context": readonly [string, string];
  readonly id: string;
  readonly verificationMethod: readonly [Ed25519VerificationMethod2020];
  readonly assertionMethod: readonly [string];
}

export function didWebFromDomain(domain: string, path: readonly string[] = []): string {
  const encodedDomain = domain.replace(":", "%3A");
  return path.length === 0
    ? `did:web:${encodedDomain}`
    : `did:web:${encodedDomain}:${path.join(":")}`;
}

/**
 * Reverses `didWebFromDomain`: the URL a resolver must fetch to get this
 * DID's document, per the did:web method spec. `localhost`/`127.0.0.1` are
 * resolved over `http` (the spec's carve-out for local development); every
 * other domain resolves over `https`.
 */
export function didWebToResolutionUrl(did: string): string {
  const DID_WEB_PREFIX = "did:web:";
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new Error(`not a did:web DID: ${did}`);
  }
  const segments = did.slice(DID_WEB_PREFIX.length).split(":");
  const domain = (segments[0] ?? "").replace("%3A", ":");
  const path = segments.slice(1);
  const hostname = domain.split(":")[0];
  const scheme = hostname === "localhost" || hostname === "127.0.0.1" ? "http" : "https";
  const pathSuffix = path.length === 0 ? "/.well-known" : `/${path.join("/")}`;
  return `${scheme}://${domain}${pathSuffix}/did.json`;
}

export function buildDidWebDocument(params: {
  readonly domain: string;
  readonly path?: readonly string[];
  readonly publicKey: Uint8Array;
}): DidWebDocument {
  const did = didWebFromDomain(params.domain, params.path);
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

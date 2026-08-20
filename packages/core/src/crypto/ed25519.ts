import { sha512 } from "@noble/hashes/sha2.js";
import * as ed25519 from "@noble/ed25519";

// @noble/ed25519 v2 ships only the async API by default; wiring in a sync
// sha512 lets us use the sync sign/verify/getPublicKey functions below.
ed25519.etc.sha512Sync = (...messages: Uint8Array[]) =>
  sha512(ed25519.etc.concatBytes(...messages));

export interface Ed25519KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export function generateKeyPair(): Ed25519KeyPair {
  const secretKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  return { publicKey, secretKey };
}

export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

/**
 * Never throws: malformed signatures, messages, or keys are exactly the
 * inputs an attacker controls, so any failure to parse or verify fails
 * closed as `false` rather than propagating an exception.
 */
export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

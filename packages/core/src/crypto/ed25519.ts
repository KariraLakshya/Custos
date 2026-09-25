import { sha512 } from "@noble/hashes/sha2.js";
import * as ed25519 from "@noble/ed25519";

// @noble/ed25519 v3 leaves the synchronous API's hash slot unset; providing
// sha512 enables the sync sign/verify/getPublicKey functions used below.
// (v2 spelled this `etc.sha512Sync` and passed a variadic message list that
// the caller had to concatenate; v3 takes a single already-joined message.)
ed25519.hashes.sha512 = sha512;

export interface Ed25519KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export function generateKeyPair(): Ed25519KeyPair {
  // v3 renamed `utils.randomPrivateKey` to `utils.randomSecretKey`.
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  return { publicKey, secretKey };
}

/** An Ed25519 secret key is its 32-byte seed; the public key is derived from it. */
export function publicKeyFromSecretKey(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secretKey);
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

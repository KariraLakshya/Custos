import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import type { SecretCipher } from "./secret-cipher.js";

const KEY_LENGTH = 32;
const NONCE_LENGTH = 24;

/**
 * Local development `SecretCipher`: XChaCha20-Poly1305 (audited AEAD, see
 * CLAUDE.md section 4 — `@noble/*` only) keyed by a caller-supplied 32-byte
 * key that lives only in this process's memory, never disk, logs, or version
 * control. A production deployment swaps this for AWS KMS envelope
 * encryption behind the same `SecretCipher` interface. AEAD authentication
 * means tampered ciphertext fails `decrypt` closed rather than silently
 * returning garbage plaintext.
 */
export function createLocalSecretCipher(key: Uint8Array): SecretCipher {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`secret cipher key must be ${KEY_LENGTH} bytes, got ${key.length}`);
  }

  return {
    async encrypt(plaintext) {
      const nonce = randomBytes(NONCE_LENGTH);
      const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext);
      return { ciphertext, nonce };
    },
    async decrypt(encrypted) {
      return xchacha20poly1305(key, encrypted.nonce).decrypt(encrypted.ciphertext);
    },
  };
}

import { generateKeyPair, sign } from "../crypto/ed25519.js";
import { publicKeyToMultibase } from "../did/did-web.js";
import type { KeyProvider } from "./key-provider.js";

/**
 * Local development `KeyProvider`: secret keys live only in this process's
 * memory (never disk, logs, or version control — CLAUDE.md section 4) and
 * are gone the moment the process exits. A production deployment swaps this
 * for an AWS KMS-backed implementation of the same interface.
 */
export function createLocalKeyProvider(): KeyProvider {
  const secretKeys = new Map<string, Uint8Array>();

  return {
    async createKeyPair() {
      const { publicKey, secretKey } = generateKeyPair();
      const keyId = publicKeyToMultibase(publicKey);
      secretKeys.set(keyId, secretKey);
      return { keyId, publicKey };
    },
    async sign(keyId, message) {
      const secretKey = secretKeys.get(keyId);
      if (!secretKey) {
        throw new Error(`unknown key id: ${keyId}`);
      }
      return sign(message, secretKey);
    },
  };
}

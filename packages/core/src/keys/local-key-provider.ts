import { generateKeyPair, publicKeyFromSecretKey, sign } from "../crypto/ed25519.js";
import { publicKeyToMultibase } from "../did/did-web.js";
import type { KeyProvider } from "./key-provider.js";

/**
 * Local development `KeyProvider`: secret keys live only in this process's
 * memory (never disk, logs, or version control — CLAUDE.md section 4) and
 * are gone the moment the process exits. A production deployment swaps this
 * for an AWS KMS-backed implementation of the same interface.
 *
 * `importedKeys` (key id → 32-byte seed) gives a dev deployment a key that
 * survives restarts, for an issuer whose signatures must stay valid
 * (ADR 0007 decision 4). The caller supplies the seed — typically from an
 * environment variable, the same precedent as `VAULT_MASTER_KEY` — so this
 * module stays free of I/O.
 */
export function createLocalKeyProvider(options?: {
  readonly importedKeys?: Readonly<Record<string, Uint8Array>>;
}): KeyProvider {
  const secretKeys = new Map<string, Uint8Array>();
  for (const [keyId, seed] of Object.entries(options?.importedKeys ?? {})) {
    if (seed.length !== 32) {
      throw new Error(`imported key ${keyId} must be 32 bytes, got ${seed.length}`);
    }
    secretKeys.set(keyId, seed);
  }

  function secretKeyFor(keyId: string): Uint8Array {
    const secretKey = secretKeys.get(keyId);
    if (!secretKey) {
      throw new Error(`unknown key id: ${keyId}`);
    }
    return secretKey;
  }

  return {
    async createKeyPair() {
      const { publicKey, secretKey } = generateKeyPair();
      const keyId = publicKeyToMultibase(publicKey);
      secretKeys.set(keyId, secretKey);
      return { keyId, publicKey };
    },
    async sign(keyId, message) {
      return sign(message, secretKeyFor(keyId));
    },
    async getPublicKey(keyId) {
      return publicKeyFromSecretKey(secretKeyFor(keyId));
    },
  };
}

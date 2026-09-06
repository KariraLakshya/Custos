/**
 * KMS-shaped encryption boundary, the same pattern as `KeyProvider`
 * (CLAUDE.md section 4): callers never see the symmetric key, only ciphertext
 * in and plaintext out. A real KMS-backed implementation (envelope
 * encryption) and `createLocalSecretCipher`'s in-memory-key one are
 * interchangeable behind this interface.
 */
export interface EncryptedSecret {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
}

export interface SecretCipher {
  readonly encrypt: (plaintext: Uint8Array) => Promise<EncryptedSecret>;
  readonly decrypt: (encrypted: EncryptedSecret) => Promise<Uint8Array>;
}

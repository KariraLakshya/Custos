/**
 * KMS-shaped signing boundary (CLAUDE.md section 4): callers get a public
 * key and an opaque `keyId` handle, never the private key material. A real
 * KMS-backed implementation and `createLocalKeyProvider`'s in-memory one
 * are interchangeable behind this interface.
 */
export interface KeyProvider {
  readonly createKeyPair: () => Promise<{
    readonly keyId: string;
    readonly publicKey: Uint8Array;
  }>;
  readonly sign: (keyId: string, message: Uint8Array) => Promise<Uint8Array>;
}

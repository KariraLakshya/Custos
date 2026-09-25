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
  /**
   * The public key of an existing key. Lets a service use a long-lived key
   * provisioned out of band (a KMS key, a dev seed) rather than minting a
   * new one per boot — an issuer key must outlive restarts (ADR 0007).
   */
  readonly getPublicKey: (keyId: string) => Promise<Uint8Array>;
}

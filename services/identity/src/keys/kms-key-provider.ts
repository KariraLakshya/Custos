import {
  CreateKeyCommand,
  GetPublicKeyCommand,
  SignCommand,
  type KMSClient,
} from "@aws-sdk/client-kms";
import type { KeyProvider } from "@custos/core";

// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE,
// AlgorithmIdentifier { id-Ed25519 1.3.101.112 }, BIT STRING of 32 bytes.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const ED25519_SPKI_LENGTH = ED25519_SPKI_PREFIX.length + 32;

// KMS accepts at most 4096 bytes for a MessageType: RAW signing request.
const MAX_RAW_MESSAGE_BYTES = 4096;

/** KMS returns public keys as DER SPKI; Custos uses raw 32-byte Ed25519 keys. Anything else is refused. */
function rawEd25519PublicKey(spki: Uint8Array | undefined): Uint8Array {
  if (
    spki?.length !== ED25519_SPKI_LENGTH ||
    !ED25519_SPKI_PREFIX.every((byte, i) => spki[i] === byte)
  ) {
    throw new Error("KMS returned a key that is not an Ed25519 public key");
  }
  return spki.slice(ED25519_SPKI_PREFIX.length);
}

/**
 * AWS KMS-backed `KeyProvider` (ADR 0002; ADR 0007 decision 4): the private
 * key is generated inside KMS and never leaves it. Signing is pure Ed25519
 * (`ED25519_SHA_512` over the raw message), so signatures verify with
 * `@custos/core`'s `verify` exactly like the local provider's.
 *
 * Use `getPublicKey`/`sign` with a key provisioned out of band for anything
 * long-lived, such as the identity service's issuer key. `createKeyPair`
 * creates a new, billed KMS key on every call — never call it per boot.
 *
 * Takes the client rather than building one, so credentials and region come
 * from the deployment's standard AWS configuration.
 */
export function createKmsKeyProvider(client: Pick<KMSClient, "send">): KeyProvider {
  async function getPublicKey(keyId: string): Promise<Uint8Array> {
    const response = await client.send(new GetPublicKeyCommand({ KeyId: keyId }));
    return rawEd25519PublicKey(response.PublicKey);
  }

  return {
    async createKeyPair() {
      const created = await client.send(
        new CreateKeyCommand({ KeySpec: "ECC_NIST_EDWARDS25519", KeyUsage: "SIGN_VERIFY" }),
      );
      const keyId = created.KeyMetadata?.KeyId;
      if (!keyId) {
        throw new Error("KMS CreateKey returned no key id");
      }
      return { keyId, publicKey: await getPublicKey(keyId) };
    },

    async sign(keyId, message) {
      if (message.length > MAX_RAW_MESSAGE_BYTES) {
        throw new Error(
          `message is ${message.length} bytes; KMS signs at most ${MAX_RAW_MESSAGE_BYTES} raw bytes`,
        );
      }
      const response = await client.send(
        new SignCommand({
          KeyId: keyId,
          Message: message,
          MessageType: "RAW",
          SigningAlgorithm: "ED25519_SHA_512",
        }),
      );
      if (response.Signature?.length !== 64) {
        throw new Error("KMS did not return a 64-byte Ed25519 signature");
      }
      return response.Signature;
    },

    getPublicKey,
  };
}

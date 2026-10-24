import { CreateKeyCommand, GetPublicKeyCommand, SignCommand } from "@aws-sdk/client-kms";
import { generateKeyPair, sign } from "@custos/core";
import type { KmsClient } from "./client.js";

// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); KMS returns keys in this form.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

type SentCommand = CreateKeyCommand | GetPublicKeyCommand | SignCommand;

export interface FakeKms {
  readonly client: KmsClient;
  /** Every command received, in order. */
  readonly sent: SentCommand[];
  /** Keys by id; add one to stand in for a key provisioned out of band. */
  readonly keys: Map<string, { publicKey: Uint8Array; secretKey: Uint8Array }>;
}

/**
 * A stand-in for AWS KMS: receives the real SDK command objects, holds real
 * Ed25519 keys, and signs for real — so a signature it returns verifies
 * exactly as a KMS one would. Records every command for request-shape checks.
 * For tests only (`@custos/kms/testing`).
 */
export function fakeKms(overrides?: {
  publicKey?: (spki: Uint8Array) => Uint8Array | undefined;
  signature?: (signature: Uint8Array) => Uint8Array | undefined;
  keyId?: string | undefined;
}): FakeKms {
  const keys = new Map<string, { publicKey: Uint8Array; secretKey: Uint8Array }>();
  const sent: SentCommand[] = [];
  let next = 0;

  const client = {
    async send(command: SentCommand) {
      sent.push(command);
      if (command instanceof CreateKeyCommand) {
        const keyId = `key-${++next}`;
        keys.set(keyId, generateKeyPair());
        return {
          KeyMetadata: {
            KeyId: overrides && "keyId" in overrides ? overrides.keyId : keyId,
          },
        };
      }
      const key = keys.get(command.input.KeyId ?? "");
      if (!key) throw new Error("NotFoundException");
      if (command instanceof GetPublicKeyCommand) {
        const spki = new Uint8Array([...ED25519_SPKI_PREFIX, ...key.publicKey]);
        return { PublicKey: overrides?.publicKey ? overrides.publicKey(spki) : spki };
      }
      const signature = sign(command.input.Message ?? new Uint8Array(), key.secretKey);
      return { Signature: overrides?.signature ? overrides.signature(signature) : signature };
    },
  };

  return { client: client as unknown as KmsClient, sent, keys };
}

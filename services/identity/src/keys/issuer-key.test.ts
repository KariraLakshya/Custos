import { GetPublicKeyCommand, type KMSClient } from "@aws-sdk/client-kms";
import { generateKeyPair, verify } from "@custos/core";
import { describe, expect, it } from "vitest";
import { loadIdentityEnv } from "../env.js";
import { createIssuerKey } from "./issuer-key.js";

const SERVICE_KEY = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

const message = new TextEncoder().encode("hello");

describe("createIssuerKey", () => {
  it("builds a local key from the seed that is stable across calls — i.e. across restarts", async () => {
    const env = loadIdentityEnv({
      IDENTITY_SERVICE_KEY: SERVICE_KEY,
      IDENTITY_ISSUER_SEED: "ab".repeat(32),
    });

    const first = createIssuerKey(env);
    const afterRestart = createIssuerKey(env);
    const publicKey = await first.keyProvider.getPublicKey(first.keyId);

    expect(await afterRestart.keyProvider.getPublicKey(afterRestart.keyId)).toEqual(publicKey);
    expect(verify(await first.keyProvider.sign(first.keyId, message), message, publicKey)).toBe(
      true,
    );
  });

  it("uses the configured KMS key id, through the given client", async () => {
    const env = loadIdentityEnv({
      IDENTITY_SERVICE_KEY: SERVICE_KEY,
      IDENTITY_KEY_PROVIDER: "kms",
      IDENTITY_ISSUER_KMS_KEY_ID: "arn:aws:kms:ap-southeast-1:111122223333:key/abc",
    });
    const { publicKey } = generateKeyPair();
    const seen: string[] = [];
    const client = {
      async send(command: GetPublicKeyCommand) {
        seen.push(command.input.KeyId ?? "");
        const spki = Uint8Array.from([
          0x30,
          0x2a,
          0x30,
          0x05,
          0x06,
          0x03,
          0x2b,
          0x65,
          0x70,
          0x03,
          0x21,
          0x00,
          ...publicKey,
        ]);
        return { PublicKey: spki };
      },
    } as unknown as KMSClient;

    const issuerKey = createIssuerKey(env, { kmsClient: client });

    expect(issuerKey.keyId).toBe("arn:aws:kms:ap-southeast-1:111122223333:key/abc");
    expect(await issuerKey.keyProvider.getPublicKey(issuerKey.keyId)).toEqual(publicKey);
    expect(seen).toEqual(["arn:aws:kms:ap-southeast-1:111122223333:key/abc"]);
  });

  it("builds a default AWS client for KMS when none is given, without contacting AWS", () => {
    const env = loadIdentityEnv({
      IDENTITY_SERVICE_KEY: SERVICE_KEY,
      IDENTITY_KEY_PROVIDER: "kms",
      IDENTITY_ISSUER_KMS_KEY_ID: "k",
    });
    expect(createIssuerKey(env).keyId).toBe("k");
  });
});

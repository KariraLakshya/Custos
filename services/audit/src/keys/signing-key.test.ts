import { generateKeyPair } from "@custos/core";
import { fakeKms } from "@custos/kms/testing";
import { describe, expect, it } from "vitest";
import { loadAuditEnv } from "../env.js";
import { createSigningKey } from "./signing-key.js";

const KEY_ARN = "arn:aws:kms:ap-south-1:111122223333:key/audit";

describe("createSigningKey (ADR 0017)", () => {
  it("derives the same key from the same seed, so seals verify across restarts", async () => {
    const env = { AUDIT_SIGNING_SEED: "11".repeat(32) };
    const first = createSigningKey(env);
    const again = createSigningKey(env);
    expect(await again.keyProvider.getPublicKey(again.keyId)).toEqual(
      await first.keyProvider.getPublicKey(first.keyId),
    );
  });

  it("uses the configured KMS key through the given client, never creating one", async () => {
    const kms = fakeKms();
    const key = generateKeyPair();
    kms.keys.set(KEY_ARN, key);
    const env = loadAuditEnv({ AUDIT_KEY_PROVIDER: "kms", AUDIT_SIGNING_KMS_KEY_ID: KEY_ARN });

    const signingKey = createSigningKey(env, { kmsClient: kms.client });

    expect(signingKey.keyId).toBe(KEY_ARN);
    expect(await signingKey.keyProvider.getPublicKey(KEY_ARN)).toEqual(key.publicKey);
    expect(kms.sent.map((command) => command.constructor.name)).toEqual(["GetPublicKeyCommand"]);
  });

  it("fails when the KMS key cannot be read, so boot (which reads it) is refused", async () => {
    const env = loadAuditEnv({ AUDIT_KEY_PROVIDER: "kms", AUDIT_SIGNING_KMS_KEY_ID: KEY_ARN });
    const signingKey = createSigningKey(env, { kmsClient: fakeKms().client });
    await expect(signingKey.keyProvider.getPublicKey(KEY_ARN)).rejects.toThrow(/NotFound/);
  });

  it("builds a default AWS client when none is given, without contacting AWS", () => {
    const env = loadAuditEnv({ AUDIT_KEY_PROVIDER: "kms", AUDIT_SIGNING_KMS_KEY_ID: KEY_ARN });
    expect(createSigningKey(env).keyId).toBe(KEY_ARN);
  });
});

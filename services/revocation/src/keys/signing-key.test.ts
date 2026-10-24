import { generateKeyPair, verify } from "@custos/core";
import { fakeKms } from "@custos/kms/testing";
import { describe, expect, it } from "vitest";
import { loadRevocationEnv } from "../env.js";
import { createSigningKey } from "./signing-key.js";

const seed = (fill: number): string => Buffer.alloc(32, fill).toString("hex");
const local = (fill: number) => ({ REVOCATION_SIGNING_SEED: seed(fill) });
const KEY_ARN = "arn:aws:kms:ap-south-1:111122223333:key/revocation";
const SERVICE_KEY = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

describe("createSigningKey (ADR 0012)", () => {
  it("derives the same public key from the same seed, independently each time", async () => {
    const first = createSigningKey(local(1));
    const second = createSigningKey(local(1));

    expect(await second.keyProvider.getPublicKey(second.keyId)).toEqual(
      await first.keyProvider.getPublicKey(first.keyId),
    );
  });

  it("derives a different public key from a different seed", async () => {
    const first = createSigningKey(local(1));
    const other = createSigningKey(local(2));

    expect(await other.keyProvider.getPublicKey(other.keyId)).not.toEqual(
      await first.keyProvider.getPublicKey(first.keyId),
    );
  });

  it("signs deterministically, so a restarted service re-serves identical signatures", async () => {
    const data = new TextEncoder().encode("tombstone");
    const first = createSigningKey(local(1));
    const second = createSigningKey(local(1));

    expect(await second.keyProvider.sign(second.keyId, data)).toEqual(
      await first.keyProvider.sign(first.keyId, data),
    );
  });
});

describe("createSigningKey with KMS (ADR 0016)", () => {
  const kmsEnv = loadRevocationEnv({
    REVOCATION_SERVICE_KEY: SERVICE_KEY,
    REVOCATION_KEY_PROVIDER: "kms",
    REVOCATION_SIGNING_KMS_KEY_ID: KEY_ARN,
  });

  it("uses the configured KMS key id, through the given client, and needs no seed", async () => {
    const kms = fakeKms();
    const key = generateKeyPair();
    kms.keys.set(KEY_ARN, key);
    const data = new TextEncoder().encode("tombstone");

    const signingKey = createSigningKey(kmsEnv, { kmsClient: kms.client });

    expect(signingKey.keyId).toBe(KEY_ARN);
    expect(await signingKey.keyProvider.getPublicKey(signingKey.keyId)).toEqual(key.publicKey);
    expect(
      verify(await signingKey.keyProvider.sign(signingKey.keyId, data), data, key.publicKey),
    ).toBe(true);
    // Only the provisioned key is used: never CreateKey, which bills a new key.
    expect(kms.sent.map((command) => command.constructor.name)).toEqual([
      "GetPublicKeyCommand",
      "SignCommand",
    ]);
  });

  it("fails when the KMS key cannot be read, so boot (which reads it) is refused", async () => {
    const signingKey = createSigningKey(kmsEnv, { kmsClient: fakeKms().client });

    await expect(signingKey.keyProvider.getPublicKey(signingKey.keyId)).rejects.toThrow(
      /NotFoundException/,
    );
  });

  it("builds a default AWS client when none is given, without contacting AWS", () => {
    expect(createSigningKey(kmsEnv).keyId).toBe(KEY_ARN);
  });
});

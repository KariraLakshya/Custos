import type { CreateKeyCommand, SignCommand } from "@aws-sdk/client-kms";
import { verify } from "@custos/core";
import { describe, expect, it } from "vitest";
import { createKmsKeyProvider } from "./kms-key-provider.js";
import { fakeKms } from "./testing.js";

const message = new TextEncoder().encode("hello");

describe("createKmsKeyProvider", () => {
  it("creates an Ed25519 signing key in KMS and returns its raw 32-byte public key", async () => {
    const kms = fakeKms();
    const provider = createKmsKeyProvider(kms.client);

    const { keyId, publicKey } = await provider.createKeyPair();

    expect(keyId).toBe("key-1");
    expect(publicKey).toEqual(kms.keys.get("key-1")?.publicKey);
    const create = kms.sent[0] as CreateKeyCommand;
    expect(create.input).toMatchObject({
      KeySpec: "ECC_NIST_EDWARDS25519",
      KeyUsage: "SIGN_VERIFY",
    });
  });

  it("signs with pure Ed25519 over the raw message, verifiable with @custos/core", async () => {
    const kms = fakeKms();
    const provider = createKmsKeyProvider(kms.client);
    const { keyId, publicKey } = await provider.createKeyPair();

    const signature = await provider.sign(keyId, message);

    expect(verify(signature, message, publicKey)).toBe(true);
    const signCommand = kms.sent.at(-1) as SignCommand;
    expect(signCommand.input).toMatchObject({
      KeyId: keyId,
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    });
  });

  it("uses an existing key by id — the restart-stable path (ADR 0007 decision 4)", async () => {
    const kms = fakeKms();
    const { keyId, publicKey } = await createKmsKeyProvider(kms.client).createKeyPair();

    // A fresh provider, as after a service restart: nothing held in memory.
    const afterRestart = createKmsKeyProvider(kms.client);

    expect(await afterRestart.getPublicKey(keyId)).toEqual(publicKey);
    expect(verify(await afterRestart.sign(keyId, message), message, publicKey)).toBe(true);
  });

  it("rejects a public key that is not Ed25519 rather than using it", async () => {
    // A P-256 SPKI has a different algorithm identifier and length.
    const kms = fakeKms({ publicKey: (spki) => new Uint8Array([0x30, 0x59, ...spki.slice(2)]) });
    const provider = createKmsKeyProvider(kms.client);

    await expect(provider.createKeyPair()).rejects.toThrow(/not an Ed25519 public key/);
  });

  it("rejects a public key with the right prefix but the wrong length", async () => {
    const kms = fakeKms({ publicKey: (spki) => spki.slice(0, 40) });
    await expect(createKmsKeyProvider(kms.client).createKeyPair()).rejects.toThrow(
      /not an Ed25519 public key/,
    );
  });

  it("rejects a response with no public key", async () => {
    const kms = fakeKms({ publicKey: () => undefined });
    await expect(createKmsKeyProvider(kms.client).createKeyPair()).rejects.toThrow(
      /not an Ed25519 public key/,
    );
  });

  it("rejects a CreateKey response with no key id", async () => {
    const kms = fakeKms({ keyId: undefined });
    await expect(createKmsKeyProvider(kms.client).createKeyPair()).rejects.toThrow(/no key id/);
  });

  it("rejects a signature that is not 64 bytes", async () => {
    const kms = fakeKms({ signature: (signature) => signature.slice(0, 63) });
    const provider = createKmsKeyProvider(kms.client);
    const { keyId } = await provider.createKeyPair();

    await expect(provider.sign(keyId, message)).rejects.toThrow(/64-byte Ed25519 signature/);
  });

  it("rejects a missing signature", async () => {
    const kms = fakeKms({ signature: () => undefined });
    const provider = createKmsKeyProvider(kms.client);
    const { keyId } = await provider.createKeyPair();

    await expect(provider.sign(keyId, message)).rejects.toThrow(/64-byte Ed25519 signature/);
  });

  it("refuses a message over KMS's 4096-byte RAW limit before calling KMS", async () => {
    const kms = fakeKms();
    const provider = createKmsKeyProvider(kms.client);
    const { keyId } = await provider.createKeyPair();
    const sentBefore = kms.sent.length;

    await expect(provider.sign(keyId, new Uint8Array(4097))).rejects.toThrow(/4096/);
    expect(kms.sent.length).toBe(sentBefore);
  });

  it("propagates a KMS failure (e.g. unknown key) as an error", async () => {
    const provider = createKmsKeyProvider(fakeKms().client);
    await expect(provider.sign("no-such-key", message)).rejects.toThrow(/NotFoundException/);
  });
});

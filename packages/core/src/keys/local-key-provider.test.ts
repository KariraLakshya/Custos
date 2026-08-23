import { describe, expect, it } from "vitest";
import { verify } from "../crypto/ed25519.js";
import { createLocalKeyProvider } from "./local-key-provider.js";

describe("createLocalKeyProvider", () => {
  it("creates independent key pairs with distinct key ids", async () => {
    const provider = createLocalKeyProvider();
    const a = await provider.createKeyPair();
    const b = await provider.createKeyPair();

    expect(a.keyId).not.toBe(b.keyId);
    expect(a.publicKey).not.toEqual(b.publicKey);
  });

  it("signs with the secret key matching a given key id, verifiable against its public key", async () => {
    const provider = createLocalKeyProvider();
    const { keyId, publicKey } = await provider.createKeyPair();
    const message = new TextEncoder().encode("hello");

    const signature = await provider.sign(keyId, message);

    expect(verify(signature, message, publicKey)).toBe(true);
  });

  it("never signs with the wrong key pair's secret", async () => {
    const provider = createLocalKeyProvider();
    const a = await provider.createKeyPair();
    const b = await provider.createKeyPair();
    const message = new TextEncoder().encode("hello");

    const signature = await provider.sign(a.keyId, message);

    expect(verify(signature, message, b.publicKey)).toBe(false);
  });

  it("rejects signing with an unknown key id", async () => {
    const provider = createLocalKeyProvider();
    await expect(provider.sign("unknown", new Uint8Array())).rejects.toThrow(/unknown key id/);
  });
});

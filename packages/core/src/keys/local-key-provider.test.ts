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

  it("returns the public key of a key it created", async () => {
    const provider = createLocalKeyProvider();
    const { keyId, publicKey } = await provider.createKeyPair();

    expect(await provider.getPublicKey(keyId)).toEqual(publicKey);
  });

  it("rejects a public key lookup for an unknown key id", async () => {
    const provider = createLocalKeyProvider();
    await expect(provider.getPublicKey("unknown")).rejects.toThrow(/unknown key id/);
  });

  describe("imported keys (a stable dev issuer key, ADR 0007 decision 4)", () => {
    const seed = new Uint8Array(32).fill(7);
    const message = new TextEncoder().encode("hello");

    it("signs with an imported key under the caller's key id", async () => {
      const provider = createLocalKeyProvider({ importedKeys: { issuer: seed } });

      const publicKey = await provider.getPublicKey("issuer");
      const signature = await provider.sign("issuer", message);

      expect(verify(signature, message, publicKey)).toBe(true);
    });

    it("is stable across restarts: a new provider from the same seed has the same key", async () => {
      const before = createLocalKeyProvider({ importedKeys: { issuer: seed } });
      const signedBeforeRestart = await before.sign("issuer", message);

      const afterRestart = createLocalKeyProvider({ importedKeys: { issuer: seed } });
      const publicKey = await afterRestart.getPublicKey("issuer");

      expect(publicKey).toEqual(await before.getPublicKey("issuer"));
      expect(verify(signedBeforeRestart, message, publicKey)).toBe(true);
    });

    it("gives different seeds different keys", async () => {
      const provider = createLocalKeyProvider({
        importedKeys: { a: seed, b: new Uint8Array(32).fill(8) },
      });

      expect(await provider.getPublicKey("a")).not.toEqual(await provider.getPublicKey("b"));
    });

    it.each([0, 31, 33, 64])("rejects a %i-byte seed at construction", (length) => {
      expect(() =>
        createLocalKeyProvider({ importedKeys: { issuer: new Uint8Array(length) } }),
      ).toThrow(/32 bytes/);
    });

    it("still creates ephemeral keys alongside imported ones", async () => {
      const provider = createLocalKeyProvider({ importedKeys: { issuer: seed } });
      const created = await provider.createKeyPair();

      expect(created.publicKey).not.toEqual(await provider.getPublicKey("issuer"));
      expect(verify(await provider.sign(created.keyId, message), message, created.publicKey)).toBe(
        true,
      );
    });
  });
});

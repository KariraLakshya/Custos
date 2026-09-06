import { describe, expect, it } from "vitest";
import { createLocalSecretCipher } from "./local-secret-cipher.js";

function key(byte = 1): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

describe("createLocalSecretCipher", () => {
  it("rejects a key of the wrong length", () => {
    expect(() => createLocalSecretCipher(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it("round-trips plaintext through encrypt/decrypt", async () => {
    const cipher = createLocalSecretCipher(key());
    const plaintext = new TextEncoder().encode("sk_test_super-secret");

    const encrypted = await cipher.encrypt(plaintext);
    const decrypted = await cipher.decrypt(encrypted);

    expect(new TextDecoder().decode(decrypted)).toBe("sk_test_super-secret");
  });

  it("uses a fresh nonce per encryption", async () => {
    const cipher = createLocalSecretCipher(key());
    const plaintext = new TextEncoder().encode("same-secret");

    const a = await cipher.encrypt(plaintext);
    const b = await cipher.encrypt(plaintext);

    expect(a.nonce).not.toEqual(b.nonce);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });

  it("fails closed when decrypting with the wrong key", async () => {
    const encrypted = await createLocalSecretCipher(key(1)).encrypt(
      new TextEncoder().encode("secret"),
    );

    await expect(createLocalSecretCipher(key(2)).decrypt(encrypted)).rejects.toThrow();
  });

  it("fails closed when the ciphertext has been tampered with", async () => {
    const cipher = createLocalSecretCipher(key());
    const encrypted = await cipher.encrypt(new TextEncoder().encode("secret"));
    const tampered = {
      nonce: encrypted.nonce,
      ciphertext: encrypted.ciphertext.map((byte, i) => (i === 0 ? byte ^ 0xff : byte)),
    };

    await expect(cipher.decrypt(tampered)).rejects.toThrow();
  });
});

import { describe, expect, it } from "vitest";
import { generateKeyPair, sign, verify } from "./ed25519.js";

describe("ed25519", () => {
  it("generates a 32-byte public key and 32-byte secret key", () => {
    const keyPair = generateKeyPair();
    expect(keyPair.publicKey).toHaveLength(32);
    expect(keyPair.secretKey).toHaveLength(32);
  });

  it("generates a different key pair on every call", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(a.secretKey).not.toEqual(b.secretKey);
  });

  it("verifies a signature produced by sign()", () => {
    const { publicKey, secretKey } = generateKeyPair();
    const message = new TextEncoder().encode("hello custos");
    const signature = sign(message, secretKey);
    expect(verify(signature, message, publicKey)).toBe(true);
  });

  it("rejects a signature after the message is tampered with", () => {
    const { publicKey, secretKey } = generateKeyPair();
    const message = new TextEncoder().encode("original message");
    const signature = sign(message, secretKey);
    const tampered = new TextEncoder().encode("tampered message");
    expect(verify(signature, tampered, publicKey)).toBe(false);
  });

  it("rejects a signature verified against the wrong public key", () => {
    const signer = generateKeyPair();
    const other = generateKeyPair();
    const message = new TextEncoder().encode("hello custos");
    const signature = sign(message, signer.secretKey);
    expect(verify(signature, message, other.publicKey)).toBe(false);
  });

  it("rejects a corrupted (single flipped byte) signature", () => {
    const { publicKey, secretKey } = generateKeyPair();
    const message = new TextEncoder().encode("hello custos");
    const signature = sign(message, secretKey);
    const corrupted = signature.slice();
    corrupted[0] = (corrupted[0] ?? 0) ^ 0xff;
    expect(verify(corrupted, message, publicKey)).toBe(false);
  });

  it("fails closed instead of throwing on a malformed (wrong-length) public key", () => {
    const { secretKey } = generateKeyPair();
    const message = new TextEncoder().encode("hello custos");
    const signature = sign(message, secretKey);
    expect(verify(signature, message, new Uint8Array(10))).toBe(false);
  });

  it("fails closed instead of throwing on a malformed (wrong-length) signature", () => {
    const { publicKey } = generateKeyPair();
    const message = new TextEncoder().encode("hello custos");
    expect(verify(new Uint8Array(5), message, publicKey)).toBe(false);
  });

  it("fails closed instead of throwing on an oversized message", () => {
    const { publicKey, secretKey } = generateKeyPair();
    const message = new Uint8Array(1_000_000);
    const signature = sign(message, secretKey);
    const tamperedOversized = new Uint8Array(1_000_000);
    tamperedOversized[0] = 1;
    expect(verify(signature, tamperedOversized, publicKey)).toBe(false);
  });
});

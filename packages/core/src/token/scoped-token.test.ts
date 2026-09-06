import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import { issueScopedToken, verifyScopedToken, type ScopedTokenClaims } from "./scoped-token.js";

function claimsAt(now: Date, ttlSeconds = 60): ScopedTokenClaims {
  const iat = Math.floor(now.getTime() / 1000);
  return {
    sub: "did:web:localhost:agents:agent-1",
    tool: "stripe",
    action: "list-customers",
    iat,
    exp: iat + ttlSeconds,
  };
}

function signerFor(secretKey: Uint8Array) {
  return { sign: (data: Uint8Array) => Promise.resolve(sign(data, secretKey)) };
}

describe("issueScopedToken / verifyScopedToken", () => {
  it("issues a token that verifies against the matching public key", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const now = new Date("2026-01-01T00:00:00Z");
    const claims = claimsAt(now);

    const issued = await issueScopedToken({ claims, signer: signerFor(secretKey) });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const verified = verifyScopedToken({ token: issued.value, publicKey, now });
    expect(verified).toEqual({ ok: true, value: claims });
  });

  it("rejects a token signed by an unrelated key", async () => {
    const signerKeys = generateKeyPair();
    const otherKeys = generateKeyPair();
    const now = new Date("2026-01-01T00:00:00Z");

    const issued = await issueScopedToken({
      claims: claimsAt(now),
      signer: signerFor(signerKeys.secretKey),
    });
    if (!issued.ok) throw new Error("expected issuance to succeed");

    const verified = verifyScopedToken({
      token: issued.value,
      publicKey: otherKeys.publicKey,
      now,
    });
    expect(verified).toEqual({ ok: false, error: { code: "SIGNATURE_INVALID" } });
  });

  it("rejects a token whose claims were tampered with after signing", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const now = new Date("2026-01-01T00:00:00Z");

    const issued = await issueScopedToken({ claims: claimsAt(now), signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");

    const [claimsPart, signaturePart] = issued.value.split(".");
    const tamperedClaims: ScopedTokenClaims = { ...claimsAt(now), tool: "attacker-tool" };
    const tamperedPart = Buffer.from(JSON.stringify(tamperedClaims), "utf8").toString("base64url");
    const tampered = `${tamperedPart}.${signaturePart}`;
    expect(tamperedPart).not.toBe(claimsPart);

    const verified = verifyScopedToken({ token: tampered, publicKey, now });
    expect(verified).toEqual({ ok: false, error: { code: "SIGNATURE_INVALID" } });
  });

  it("rejects an expired token", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const issuedAt = new Date("2026-01-01T00:00:00Z");

    const issued = await issueScopedToken({
      claims: claimsAt(issuedAt),
      signer: signerFor(secretKey),
    });
    if (!issued.ok) throw new Error("expected issuance to succeed");

    const afterExpiry = new Date(issuedAt.getTime() + 61_000);
    const verified = verifyScopedToken({ token: issued.value, publicKey, now: afterExpiry });
    expect(verified).toEqual({ ok: false, error: { code: "EXPIRED" } });
  });

  it("accepts a token at the last instant before expiry", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const issuedAt = new Date("2026-01-01T00:00:00.000Z");

    const issued = await issueScopedToken({
      claims: claimsAt(issuedAt),
      signer: signerFor(secretKey),
    });
    if (!issued.ok) throw new Error("expected issuance to succeed");

    const justBeforeExpiry = new Date(issuedAt.getTime() + 59_999);
    const verified = verifyScopedToken({ token: issued.value, publicKey, now: justBeforeExpiry });
    expect(verified.ok).toBe(true);
  });

  it.each([["not-a-token"], [""], ["only.two.parts.too.many"]])(
    "rejects malformed token %j",
    (token) => {
      const { publicKey } = generateKeyPair();
      const verified = verifyScopedToken({ token, publicKey, now: new Date() });
      expect(verified.ok).toBe(false);
      if (!verified.ok) expect(verified.error.code).toBe("MALFORMED_TOKEN");
    },
  );

  it("rejects a token whose claims payload isn't a usable shape", () => {
    const { publicKey, secretKey } = generateKeyPair();
    const bogusClaims = Buffer.from(JSON.stringify({ foo: "bar" }), "utf8").toString("base64url");
    const signature = sign(Buffer.from(bogusClaims, "utf8"), secretKey);
    const token = `${bogusClaims}.${Buffer.from(signature).toString("base64url")}`;

    const verified = verifyScopedToken({ token, publicKey, now: new Date() });
    expect(verified).toEqual({
      ok: false,
      error: { code: "MALFORMED_TOKEN", reason: "claims missing required fields" },
    });
  });

  it("rejects a token whose claims payload isn't valid JSON at all", () => {
    const { publicKey } = generateKeyPair();
    const notJson = Buffer.from("not-json{", "utf8").toString("base64url");
    const token = `${notJson}.${Buffer.from("irrelevant").toString("base64url")}`;

    const verified = verifyScopedToken({ token, publicKey, now: new Date() });
    expect(verified.ok).toBe(false);
    if (!verified.ok) expect(verified.error.code).toBe("MALFORMED_TOKEN");
  });

  it("surfaces a signing failure as an error value", async () => {
    const now = new Date();
    const failingSigner = { sign: () => Promise.reject(new Error("kms unreachable")) };

    const issued = await issueScopedToken({ claims: claimsAt(now), signer: failingSigner });

    expect(issued).toEqual({
      ok: false,
      error: { code: "SIGNING_FAILED", reason: "kms unreachable" },
    });
  });
});

import { generateKeyPair, publicKeyToMultibase } from "@custos/core";
import { describe, expect, it } from "vitest";
import { parseTrustAnchors } from "./anchors.js";

function entry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    domain: "a.example",
    credentialIssuerDid: "did:web:a.example",
    credentialIssuerPublicKey: publicKeyToMultibase(generateKeyPair().publicKey),
    statusIssuerDid: "did:web:a.example:revocation",
    statusIssuerPublicKey: publicKeyToMultibase(generateKeyPair().publicKey),
    statusListId: "https://a.example/status/revocation",
    statusFetchUrl: "https://a.example/status/revocation",
    maxStatusAgeSeconds: 600,
    enabled: true,
    ...overrides,
  };
}

function issuesOf(input: unknown): string[] {
  const result = parseTrustAnchors(input);
  if (result.ok) throw new Error("expected refusal");
  return result.error.issues;
}

describe("parseTrustAnchors", () => {
  it("turns a valid entry into a core TrustAnchor with decoded keys", () => {
    const result = parseTrustAnchors([entry()]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const [anchor] = result.value;
    expect(anchor?.credentialIssuerPublicKey).toBeInstanceOf(Uint8Array);
    expect(anchor?.credentialIssuerPublicKey.length).toBe(32);
    expect(anchor?.statusFetchUrl).toBe("https://a.example/status/revocation");
    expect(anchor?.enabled).toBe(true);
  });

  it("accepts an empty set (B trusts nobody)", () => {
    expect(parseTrustAnchors([])).toEqual({ ok: true, value: [] });
  });

  it("refuses anything that is not an array", () => {
    for (const input of [undefined, null, {}, "x", 7]) {
      expect(parseTrustAnchors(input).ok).toBe(false);
    }
  });

  it.each([
    ["missing maxStatusAgeSeconds", { maxStatusAgeSeconds: undefined }],
    ["zero maxStatusAgeSeconds", { maxStatusAgeSeconds: 0 }],
    ["negative maxStatusAgeSeconds", { maxStatusAgeSeconds: -1 }],
    ["fractional maxStatusAgeSeconds", { maxStatusAgeSeconds: 1.5 }],
    ["string maxStatusAgeSeconds", { maxStatusAgeSeconds: "600" }],
    ["missing enabled", { enabled: undefined }],
    ["string enabled", { enabled: "true" }],
    ["non-web DID", { credentialIssuerDid: "did:key:z6Mk" }],
    ["empty domain", { domain: "" }],
    ["oversized domain", { domain: "d".repeat(201) }],
    ["unknown field", { extra: 1 }],
  ])("refuses %s", (_label, overrides) => {
    expect(parseTrustAnchors([entry(overrides)]).ok).toBe(false);
  });

  it("refuses a key that is not a base58btc Ed25519 multibase key", () => {
    expect(issuesOf([entry({ credentialIssuerPublicKey: "not-a-key" })])).toContain(
      "0.credentialIssuerPublicKey: not an Ed25519 key",
    );
    expect(issuesOf([entry({ statusIssuerPublicKey: "z1111" })])).toContain(
      "0.statusIssuerPublicKey: not an Ed25519 key",
    );
  });

  it("refuses two anchors for the same credential issuer, so none silently wins", () => {
    const issues = issuesOf([entry(), entry({ statusListId: "https://a.example/other" })]);
    expect(issues).toContain("1.credentialIssuerDid: duplicate");
  });

  it("refuses two anchors for the same status list", () => {
    const issues = issuesOf([entry(), entry({ credentialIssuerDid: "did:web:b.example" })]);
    expect(issues).toContain("1.statusListId: duplicate");
  });

  it("refuses more than 64 anchors", () => {
    const many = Array.from({ length: 65 }, (_, i) =>
      entry({
        credentialIssuerDid: `did:web:o${i}.example`,
        statusListId: `https://o${i}.example/s`,
      }),
    );
    expect(parseTrustAnchors(many).ok).toBe(false);
  });
});

describe("parseTrustAnchors: the status fetch URL", () => {
  it.each([
    "https://a.example/status/revocation",
    "http://localhost:4010/status",
    "http://127.0.0.1:4010/status",
    "http://[::1]:4010/status",
  ])("accepts %s", (statusFetchUrl) => {
    expect(parseTrustAnchors([entry({ statusFetchUrl })]).ok).toBe(true);
  });

  it.each([
    "http://a.example/status",
    "http://localhost.evil.com/status",
    "http://127.0.0.1.evil.com/status",
    "http://localhost@evil.com/status",
    "https://user:pass@a.example/status",
    "ftp://a.example/status",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "not a url",
    "",
  ])("refuses %s", (statusFetchUrl) => {
    expect(parseTrustAnchors([entry({ statusFetchUrl })]).ok).toBe(false);
  });
});

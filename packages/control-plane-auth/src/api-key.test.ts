import { describe, expect, it } from "vitest";
import { generateApiKey, hashApiKeySecret, parseApiKey, secretMatchesHash } from "./api-key.js";
import { isScope, scopeAllowedFor } from "./scopes.js";

/** Deterministic randomness: byte i of every draw is `seed + i`. */
function seededBytes(seed: number): (length: number) => Uint8Array {
  return (length) => Uint8Array.from({ length }, (_, i) => (seed + i) & 0xff);
}

describe("generateApiKey / parseApiKey", () => {
  it("round-trips an operator key", () => {
    const key = generateApiKey("operator", seededBytes(1));
    expect(key.token).toMatch(/^custos_operator_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
    const parsed = parseApiKey(key.token);
    expect(parsed).toEqual({ kind: "operator", id: key.id, secret: expect.any(String) });
    expect(hashApiKeySecret(parsed!.secret)).toBe(key.secretHash);
  });

  it("round-trips a service key whose secret contains underscores", () => {
    // 0xff bytes encode to "_" in base64url, so the separator can't be a split.
    const key = generateApiKey("service", (length) => new Uint8Array(length).fill(0xff));
    expect(key.token.split("_").length).toBeGreaterThan(4);
    const parsed = parseApiKey(key.token);
    expect(parsed?.kind).toBe("service");
    expect(hashApiKeySecret(parsed!.secret)).toBe(key.secretHash);
  });

  it("never puts the secret's hash in the token", () => {
    const key = generateApiKey("operator", seededBytes(7));
    expect(key.token).not.toContain(key.secretHash);
  });

  it.each([
    ["empty", ""],
    ["wrong prefix", "custom_operator_0123456789abcdef_" + "a".repeat(43)],
    ["unknown kind", "custos_agent_0123456789abcdef_" + "a".repeat(43)],
    ["short id", "custos_operator_0123_" + "a".repeat(43)],
    ["uppercase id", "custos_operator_0123456789ABCDEF_" + "a".repeat(43)],
    ["short secret", "custos_operator_0123456789abcdef_" + "a".repeat(42)],
    ["long secret", "custos_operator_0123456789abcdef_" + "a".repeat(44)],
    ["bad secret char", "custos_operator_0123456789abcdef_" + "a".repeat(42) + "="],
    ["oversized", "custos_operator_0123456789abcdef_" + "a".repeat(10_000)],
    ["trailing newline", "custos_operator_0123456789abcdef_" + "a".repeat(43) + "\n"],
  ])("rejects a malformed key: %s", (_label, token) => {
    expect(parseApiKey(token)).toBeNull();
  });
});

describe("secretMatchesHash", () => {
  it("matches the right secret", () => {
    expect(secretMatchesHash("s3cret", hashApiKeySecret("s3cret"))).toBe(true);
  });

  it("refuses a wrong secret", () => {
    expect(secretMatchesHash("s3cret", hashApiKeySecret("other"))).toBe(false);
  });

  it("refuses a malformed stored hash instead of throwing", () => {
    expect(secretMatchesHash("s3cret", "not-a-hash")).toBe(false);
    expect(secretMatchesHash("s3cret", "ab")).toBe(false);
  });
});

describe("scopes", () => {
  it("recognises known scopes only", () => {
    expect(isScope("audit:write")).toBe(true);
    expect(isScope("audit:read")).toBe(false);
    expect(isScope("")).toBe(false);
  });

  it("keeps service-only scopes off operator keys", () => {
    expect(scopeAllowedFor("operator", "agents:register")).toBe(true);
    expect(scopeAllowedFor("operator", "audit:write")).toBe(false);
    expect(scopeAllowedFor("operator", "status:allocate")).toBe(false);
    expect(scopeAllowedFor("service", "audit:write")).toBe(true);
    expect(scopeAllowedFor("service", "agents:revoke")).toBe(true);
  });
});

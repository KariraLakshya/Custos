import { fixedClock } from "./test-clock.js";
import { describe, expect, it } from "vitest";
import { generateApiKey } from "./api-key.js";
import { createApiKeyAuthenticator } from "./authenticator.js";
import type { ApiKeyRow } from "./schema.js";
import type { PrincipalKind } from "./scopes.js";

const NOW = new Date("2026-10-02T12:00:00.000Z");
const clock = fixedClock(NOW);

function keyFixture(overrides: Partial<ApiKeyRow> & { kind?: PrincipalKind } = {}): {
  token: string;
  row: ApiKeyRow;
} {
  const kind = overrides.kind ?? "operator";
  const key = generateApiKey(kind);
  const row: ApiKeyRow = {
    id: key.id,
    kind,
    name: "lakshya",
    scopes: ["credentials:write"],
    secretHash: key.secretHash,
    createdAt: new Date("2026-10-01T00:00:00.000Z"),
    expiresAt: new Date("2026-12-31T00:00:00.000Z"),
    revokedAt: null,
    createdVia: "custos-admin",
    ...overrides,
  };
  return { token: key.token, row };
}

function authenticatorFor(...rows: ApiKeyRow[]) {
  const byId = new Map(rows.map((row) => [row.id, row]));
  return createApiKeyAuthenticator({
    keys: { findById: async (id) => byId.get(id) ?? null },
    clock,
  });
}

const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

describe("createApiKeyAuthenticator", () => {
  it("authenticates a valid key as its principal", async () => {
    const { token, row } = keyFixture({ scopes: ["credentials:write", "agents:revoke"] });
    const result = await authenticatorFor(row).authenticate(bearer(token));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toEqual({
      kind: "operator",
      id: row.id,
      name: "lakshya",
      scopes: new Set(["credentials:write", "agents:revoke"]),
    });
  });

  it("refuses a request with no authorization header", async () => {
    const result = await authenticatorFor().authenticate({ headers: {} });
    expect(result).toEqual({ ok: false, error: { reason: "MISSING" } });
  });

  it.each([
    ["not bearer", "Basic abc"],
    ["bare token", "custos_operator_0123456789abcdef_" + "a".repeat(43)],
    ["bearer garbage", "Bearer not-a-key"],
    ["two tokens", "Bearer a b"],
    ["oversized", "Bearer " + "a".repeat(10_000)],
  ])("refuses a malformed header: %s", async (_label, authorization) => {
    const result = await authenticatorFor().authenticate({ headers: { authorization } });
    expect(result).toEqual({ ok: false, error: { reason: "MALFORMED" } });
  });

  it("refuses a repeated authorization header", async () => {
    const { token, row } = keyFixture();
    const result = await authenticatorFor(row).authenticate({
      headers: { authorization: [`Bearer ${token}`, `Bearer ${token}`] },
    });
    expect(result).toEqual({ ok: false, error: { reason: "MALFORMED" } });
  });

  it("refuses an unknown key id", async () => {
    const { token } = keyFixture();
    const result = await authenticatorFor().authenticate(bearer(token));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toBe("UNKNOWN_KEY");
  });

  it("refuses a known id with the wrong secret", async () => {
    const { token, row } = keyFixture();
    const forged = token.slice(0, -1) + (token.endsWith("A") ? "B" : "A");
    const result = await authenticatorFor(row).authenticate(bearer(forged));
    expect(result).toEqual({ ok: false, error: { reason: "WRONG_SECRET", keyId: row.id } });
  });

  it("refuses a key presented with the wrong kind prefix", async () => {
    const { token, row } = keyFixture({ kind: "service", scopes: ["audit:write"] });
    const asOperator = token.replace("custos_service_", "custos_operator_");
    const result = await authenticatorFor(row).authenticate(bearer(asOperator));
    expect(result).toEqual({ ok: false, error: { reason: "KIND_MISMATCH", keyId: row.id } });
  });

  it("refuses a revoked key", async () => {
    const { token, row } = keyFixture({ revokedAt: new Date("2026-10-02T00:00:00.000Z") });
    const result = await authenticatorFor(row).authenticate(bearer(token));
    expect(result).toEqual({ ok: false, error: { reason: "REVOKED", keyId: row.id } });
  });

  it("refuses an expired key, including at the exact expiry instant", async () => {
    for (const expiresAt of [new Date("2026-10-01T00:00:00.000Z"), NOW]) {
      const { token, row } = keyFixture({ expiresAt });
      const result = await authenticatorFor(row).authenticate(bearer(token));
      expect(result).toEqual({ ok: false, error: { reason: "EXPIRED", keyId: row.id } });
    }
  });

  it("drops service-only and unknown scopes from an operator key's row", async () => {
    const { token, row } = keyFixture({
      scopes: ["agents:register", "audit:write", "status:allocate", "root"],
    });
    const result = await authenticatorFor(row).authenticate(bearer(token));
    expect(result.ok && [...result.value.scopes]).toEqual(["agents:register"]);
  });

  it("keeps service-only scopes on a service key", async () => {
    const { token, row } = keyFixture({ kind: "service", scopes: ["audit:write"] });
    const result = await authenticatorFor(row).authenticate(bearer(token));
    expect(result.ok && [...result.value.scopes]).toEqual(["audit:write"]);
  });
});

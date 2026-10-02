import { describe, expect, it } from "vitest";
import { generateApiKey } from "./api-key.js";
import { checkServiceKey, createControlPlaneGuard } from "./guard.js";
import type { ApiKeyRow } from "./schema.js";
import type { PrincipalKind } from "./scopes.js";
import { fixedClock } from "./test-clock.js";

const clock = fixedClock("2026-10-02T12:00:00.000Z");

function guardWith(kind: PrincipalKind, scopes: string[], expiresAt = "2026-12-31T00:00:00.000Z") {
  const key = generateApiKey(kind);
  const row: ApiKeyRow = {
    id: key.id,
    kind,
    name: "vault",
    scopes,
    secretHash: key.secretHash,
    createdAt: new Date("2026-10-01T00:00:00.000Z"),
    expiresAt: new Date(expiresAt),
    revokedAt: null,
  };
  const guard = createControlPlaneGuard({
    keys: { findById: async (id) => (id === row.id ? row : null) },
    clock,
  });
  return { guard, token: key.token, id: key.id };
}

describe("checkServiceKey", () => {
  it("accepts a service key with the scope", async () => {
    const { guard, token } = guardWith("service", ["audit:write"]);
    const result = await checkServiceKey({ ...guard, token, scope: "audit:write" });
    expect(result.ok && result.value.name).toBe("vault");
  });

  it("rejects a malformed key without echoing it", async () => {
    const { guard } = guardWith("service", ["audit:write"]);
    const result = await checkServiceKey({ ...guard, token: "not-a-key", scope: "audit:write" });
    expect(result).toEqual({ ok: false, error: "service key rejected: MALFORMED" });
  });

  it("rejects an expired key, naming its id but not its secret", async () => {
    const { guard, token, id } = guardWith("service", ["audit:write"], "2026-10-01T00:00:00.000Z");
    const result = await checkServiceKey({ ...guard, token, scope: "audit:write" });
    expect(result).toEqual({ ok: false, error: `service key rejected: EXPIRED (key ${id})` });
    expect(JSON.stringify(result)).not.toContain(token.slice(-43));
  });

  it("rejects an operator key in a service's place", async () => {
    const { guard, token, id } = guardWith("operator", ["agents:revoke"]);
    const result = await checkServiceKey({ ...guard, token, scope: "agents:revoke" });
    expect(result).toEqual({ ok: false, error: `key ${id} is not a service key` });
  });

  it("rejects a service key without the scope", async () => {
    const { guard, token, id } = guardWith("service", ["status:allocate"]);
    const result = await checkServiceKey({ ...guard, token, scope: "audit:write" });
    expect(result).toEqual({ ok: false, error: `service key ${id} lacks scope audit:write` });
  });
});

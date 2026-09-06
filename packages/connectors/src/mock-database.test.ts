import { describe, expect, it } from "vitest";
import { createMockDatabaseConnector } from "./mock-database.js";

describe("createMockDatabaseConnector", () => {
  it("returns canned rows for a known table", async () => {
    const connector = createMockDatabaseConnector();
    const result = await connector.call({
      action: "query",
      input: { table: "customers" },
      credential: "x",
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toHaveLength(2);
  });

  it("rejects an unknown table", async () => {
    const connector = createMockDatabaseConnector();
    const result = await connector.call({
      action: "query",
      input: { table: "nope" },
      credential: "x",
    });
    expect(result).toEqual({
      ok: false,
      error: { code: "UPSTREAM_ERROR", reason: "unknown table: nope" },
    });
  });

  it("rejects an unknown action", async () => {
    const connector = createMockDatabaseConnector();
    const result = await connector.call({ action: "drop-table", input: {}, credential: "x" });
    expect(result).toEqual({ ok: false, error: { code: "UNKNOWN_ACTION", action: "drop-table" } });
  });

  it("rejects malformed input", async () => {
    const connector = createMockDatabaseConnector();
    const result = await connector.call({ action: "query", input: {}, credential: "x" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("INVALID_INPUT");
  });

  it("revoke() is a no-op — the fake tool has no real access to revoke", async () => {
    const connector = createMockDatabaseConnector();
    await expect(connector.revoke("agent-1")).resolves.toBeUndefined();
  });
});

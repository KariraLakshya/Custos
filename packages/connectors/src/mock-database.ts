import { err, ok } from "@custos/contracts";
import { createRevocationGuard, type Connector } from "./connector.js";

const FAKE_TABLES: Record<string, readonly Record<string, unknown>[]> = {
  customers: [
    { id: 1, name: "Ada Lovelace" },
    { id: 2, name: "Alan Turing" },
  ],
};

function isQueryInput(value: unknown): value is { table: string } {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { table?: unknown }).table === "string"
  );
}

/**
 * Fake internal-database connector: no network calls, canned rows only.
 * Exists to prove the vault/token pattern generalizes across more than one
 * tool (CLAUDE.md's Phase 2 "two or three tool connectors").
 */
export function createMockDatabaseConnector(): Connector {
  const guard = createRevocationGuard();

  return {
    tool: "mock-database",
    async call({ action, input, agentId }) {
      if (guard.isRevoked(agentId)) {
        return err({ code: "AGENT_REVOKED", agentId });
      }
      if (action !== "query") {
        return err({ code: "UNKNOWN_ACTION", action });
      }
      if (!isQueryInput(input)) {
        return err({ code: "INVALID_INPUT", reason: "expected { table: string }" });
      }
      const rows = FAKE_TABLES[input.table];
      if (!rows) {
        return err({ code: "UPSTREAM_ERROR", reason: `unknown table: ${input.table}` });
      }
      return ok(rows);
    },
    async revoke(agentId) {
      guard.revoke(agentId);
    },
  };
}

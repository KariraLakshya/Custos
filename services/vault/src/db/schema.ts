import { pgTable, primaryKey, text, timestamp } from "drizzle-orm/pg-core";

// Ciphertext and nonce are base64-encoded @custos/core SecretCipher output
// (see docs/adr/0004-vault-credential-encryption.md) — the plaintext
// credential is never stored, never logged.
export const toolCredentials = pgTable("tool_credentials", {
  tool: text("tool").primaryKey(),
  ciphertext: text("ciphertext").notNull(),
  nonce: text("nonce").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type ToolCredentialRow = typeof toolCredentials.$inferSelect;
export type NewToolCredentialRow = typeof toolCredentials.$inferInsert;

// One row = one agent-may-call-this-tool grant (build plan Phase 4: "simple
// allowlists per agent × tool"). Absence of a row means denied — fail closed,
// deny by default, matching every other security decision in this codebase.
export const agentPolicies = pgTable(
  "agent_policies",
  {
    agentDid: text("agent_did").notNull(),
    tool: text("tool").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [primaryKey({ columns: [table.agentDid, table.tool] })],
);

export type AgentPolicyRow = typeof agentPolicies.$inferSelect;
export type NewAgentPolicyRow = typeof agentPolicies.$inferInsert;

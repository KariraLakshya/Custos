import { pgTable, text, timestamp } from "drizzle-orm/pg-core";

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

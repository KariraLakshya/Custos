import { jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

// `id` is client-generated (not `defaultRandom()`): it must be known before
// insert, since it is embedded in the agent's did:web path and its VC.
export const agents = pgTable("agents", {
  id: uuid("id").primaryKey(),
  did: text("did").notNull().unique(),
  // Legacy (pre-ADR 0007): the identity service's KeyProvider handle for a key
  // it held on the agent's behalf. Agents now hold their own keys, so new
  // rows leave it null. Kept nullable, not dropped — no destructive migration.
  keyId: text("key_id"),
  // The agent's own public key (multibase), submitted at registration with a
  // proof of possession. Unique: one key is one agent, which also makes a
  // replayed registration request fail instead of minting a duplicate agent.
  // Null only for rows registered before ADR 0007.
  publicKeyMultibase: text("public_key_multibase").unique(),
  didDocument: jsonb("did_document").notNull(),
  credential: jsonb("credential").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AgentRow = typeof agents.$inferSelect;
export type NewAgentRow = typeof agents.$inferInsert;

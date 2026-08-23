import { jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

// `id` is client-generated (not `defaultRandom()`): it must be known before
// insert, since it is embedded in the agent's did:web path and its VC.
export const agents = pgTable("agents", {
  id: uuid("id").primaryKey(),
  did: text("did").notNull().unique(),
  // Opaque KeyProvider handle used to re-sign later — not the same thing as
  // the public key material, which lives in `didDocument` below.
  keyId: text("key_id").notNull(),
  didDocument: jsonb("did_document").notNull(),
  credential: jsonb("credential").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AgentRow = typeof agents.$inferSelect;
export type NewAgentRow = typeof agents.$inferInsert;

import { pgTable, serial, text, timestamp, uuid } from "drizzle-orm/pg-core";

/**
 * One row per registered agent. The row is created at registration time (the
 * identity service asks this service for an index before it issues the
 * agent's credential), and `revokedAt` is filled in when the agent is
 * deprovisioned — so allocation and revocation state live together and this
 * service can answer both without depending on identity being reachable.
 *
 * `statusListIndex` is a `serial`, so indexes are never reused. That matters:
 * a revoked bit is never cleared, so handing a recycled index to a fresh
 * agent would silently publish it as already-revoked.
 */
export const statusListEntries = pgTable("status_list_entries", {
  agentDid: text("agent_did").primaryKey(),
  agentId: uuid("agent_id").notNull().unique(),
  statusListIndex: serial("status_list_index").notNull().unique(),
  // NULL means active. Revocation is permanent — this is never set back.
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  reason: text("reason"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type StatusListEntryRow = typeof statusListEntries.$inferSelect;
export type NewStatusListEntryRow = typeof statusListEntries.$inferInsert;

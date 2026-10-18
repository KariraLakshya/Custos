import { integer, pgTable, serial, text, timestamp, uuid } from "drizzle-orm/pg-core";

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

/**
 * Revoked slots that came from the published status list (ADR 0014) and have no
 * row in `status_list_entries`, for example after this database was restored
 * from a backup older than the agent. They are kept so the list this service
 * serves can never clear a bit the publisher set. Rolling this back is
 * `DROP TABLE external_revoked_indexes` (nothing else refers to it).
 */
export const externalRevokedIndexes = pgTable("external_revoked_indexes", {
  statusListIndex: integer("status_list_index").primaryKey(),
  // The signed `validFrom` of the published list that first carried this bit.
  firstSeenInListAt: timestamp("first_seen_in_list_at", { withTimezone: true }).notNull(),
  mergedAt: timestamp("merged_at", { withTimezone: true }).notNull().defaultNow(),
});

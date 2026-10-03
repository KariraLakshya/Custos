import { jsonb, pgTable, serial, text, timestamp } from "drizzle-orm/pg-core";

/**
 * One row per reported action outcome (CLAUDE.md section 10). Deliberately
 * stores the *unsigned* fields, not a pre-signed envelope — the same reason
 * `services/revocation`'s tombstones are re-signed fresh on every read
 * rather than stored signed: this service's signing key is ephemeral
 * (regenerated on every process start, same as vault's and revocation's own
 * signing identities), so a record signed once and stored as-is would
 * permanently fail to verify after a restart. Signing happens only at read
 * time, against whichever key is live then (see `records/list.ts`).
 *
 * `agentDid`/`tool`/`decision` are indexed-in-spirit columns for querying;
 * `id` is a strictly increasing serial so gaps or reordering in the
 * append-only sequence are at least detectable. No update or delete route
 * exists anywhere in this service — append-only is enforced by omission,
 * not a DB-level trigger (deferred hardening, see CLAUDE.md's known issues).
 */
export const auditRecords = pgTable("audit_records", {
  id: serial("id").primaryKey(),
  // Null for a control-plane action that names no agent (ADR 0008 §7).
  agentDid: text("agent_did"),
  // The operator or service behind a control-plane action; null for an
  // agent action. Its key id and name, never the key.
  principalKind: text("principal_kind").$type<"operator" | "service">(),
  principalId: text("principal_id"),
  principalName: text("principal_name"),
  tool: text("tool"),
  action: text("action").notNull(),
  dataCategories: jsonb("data_categories").notNull().$type<readonly string[]>(),
  policyRule: text("policy_rule").notNull(),
  decision: text("decision").notNull(),
  reason: text("reason"),
  recordedAt: timestamp("recorded_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

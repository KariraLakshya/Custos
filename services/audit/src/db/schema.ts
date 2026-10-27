import { integer, jsonb, pgTable, serial, text, timestamp } from "drizzle-orm/pg-core";

/**
 * One row per reported action outcome (CLAUDE.md section 10), chained into a
 * ledger (ADR 0017). `payload` is the record exactly as hashed, serialised
 * once at append; `hash` links the row to the one before it. The other
 * columns are for queries only and are never used to rebuild a payload.
 *
 * Forks are refused by the database itself: `seq` and `prev_hash` are unique,
 * so two appends can never follow the same entry. Rows stored before the
 * ledger existed have null chain columns until the service chains them at
 * boot. No update or delete route exists; tampering is detected by the chain
 * and the seals rather than prevented.
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
  // The authenticated caller of POST /records (ADR 0017 §4); null on older rows.
  reportedByKind: text("reported_by_kind").$type<"operator" | "service">(),
  reportedById: text("reported_by_id"),
  reportedByName: text("reported_by_name"),
  // The ledger (ADR 0017 §1). Null only until the row is chained.
  seq: integer("seq").unique(),
  prevHash: text("prev_hash").unique(),
  payload: text("payload"),
  payloadHash: text("payload_hash"),
  hash: text("hash"),
});

/** Signed heads of the chain (ADR 0017 §2), one per sealed `seq`. */
export const auditSeals = pgTable("audit_seals", {
  seq: integer("seq").primaryKey(),
  headHash: text("head_hash").notNull(),
  // The signed compact envelope, stored as signed: the key is stable.
  seal: text("seal").notNull(),
  sealedAt: timestamp("sealed_at", { withTimezone: true }).notNull(),
  // The key that signed it, multibase (ADR 0017, key rotation); null on seals
  // made before keys were named. Only seals by the current key are served or copied.
  signingKey: text("signing_key"),
  // When the seal was copied to the seal store (ADR 0017 part 2a); null until then.
  pushedAt: timestamp("pushed_at", { withTimezone: true }),
});

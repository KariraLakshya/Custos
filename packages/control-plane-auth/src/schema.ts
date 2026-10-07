import { jsonb, pgTable, text, timestamp } from "drizzle-orm/pg-core";

/**
 * Operator and service API keys, shared by every service (ADR 0008 §5) —
 * acceptable while they share one Postgres; revisit if they stop.
 *
 * Only `SHA-256(secret)` is stored; the full key is shown once at creation.
 * `expiresAt` is mandatory. A key is never deleted, only revoked, so the
 * audit trail's principal ids keep resolving to a name.
 */
export const apiKeys = pgTable("api_keys", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull().$type<"operator" | "service">(),
  name: text("name").notNull(),
  scopes: jsonb("scopes").notNull().$type<readonly string[]>(),
  secretHash: text("secret_hash").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  // How the key was made: by `custos-admin`, or by an operator's SSO login
  // (ADR 0010), which makes short-lived keys named after the person.
  createdVia: text("created_via").notNull().default("custos-admin").$type<"custos-admin" | "sso">(),
});

export type ApiKeyRow = typeof apiKeys.$inferSelect;

import { auditRecords } from "../db/schema.js";
import type { AuditDb } from "../db/client.js";

export interface AuditEventInput {
  readonly agentDid: string;
  readonly tool: string;
  readonly action: string;
  readonly dataCategories: readonly string[];
  readonly policy: { readonly rule: string; readonly decision: "allow" | "deny" };
  readonly reason?: string;
}

/**
 * Stores one reported event's raw fields — unsigned (see the doc comment on
 * `auditRecords` in `../db/schema.js` for why signing is deferred to read
 * time). `authorityChain` is flat (just the agent itself) until delegation
 * exists — see the doc comment on `AuditRecord` in `@custos/core`.
 */
export async function appendAuditRecord(params: {
  readonly db: AuditDb;
  readonly event: AuditEventInput;
  readonly now: Date;
}): Promise<void> {
  const { db, event, now } = params;

  await db.insert(auditRecords).values({
    agentDid: event.agentDid,
    tool: event.tool,
    action: event.action,
    dataCategories: event.dataCategories,
    policyRule: event.policy.rule,
    decision: event.policy.decision,
    reason: event.reason ?? null,
    recordedAt: now,
  });
}

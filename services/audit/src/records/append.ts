import type { AuditEvent } from "@custos/contracts";
import { auditRecords } from "../db/schema.js";
import type { AuditDb } from "../db/client.js";

/**
 * Stores one reported event's raw fields — unsigned (see the doc comment on
 * `auditRecords` in `../db/schema.js` for why signing is deferred to read
 * time). `authorityChain` is flat (just the agent itself) until delegation
 * exists — see the doc comment on `AuditRecord` in `@custos/core`.
 */
export async function appendAuditRecord(params: {
  readonly db: AuditDb;
  readonly event: AuditEvent;
  readonly now: Date;
}): Promise<void> {
  const { db, event, now } = params;

  await db.insert(auditRecords).values({
    agentDid: event.agentDid ?? null,
    principalKind: event.principal?.kind ?? null,
    principalId: event.principal?.id ?? null,
    principalName: event.principal?.name ?? null,
    tool: event.tool ?? null,
    action: event.action,
    dataCategories: event.dataCategories,
    policyRule: event.policy.rule,
    decision: event.policy.decision,
    reason: event.reason ?? null,
    recordedAt: now,
  });
}

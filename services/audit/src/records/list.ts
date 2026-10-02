import { asc, eq } from "drizzle-orm";
import { issueAuditRecord, type AuditRecordSigner } from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { auditRecords } from "../db/schema.js";
import type { AuditDb } from "../db/client.js";

export type ListAuditRecordsError = { readonly code: "SIGNING_FAILED"; readonly reason: string };

/**
 * Every stored record, freshly signed under whichever key is live right
 * now — the same "re-sign on every read, never store pre-signed" pattern as
 * `services/revocation`'s `listTombstones()`, and for the identical reason:
 * this service's signing key is ephemeral, so a stored signature would go
 * stale across a restart while the underlying fact it attests to would not.
 * Optional `agentDid` narrows to one agent's log (build plan Phase 4: "pull
 * a verifiable log of every action every agent took").
 */
export async function listAuditRecords(params: {
  readonly db: AuditDb;
  readonly signer: AuditRecordSigner;
  readonly agentDid?: string;
}): Promise<Result<readonly string[], ListAuditRecordsError>> {
  const { db, signer, agentDid } = params;

  const rows = await db
    .select()
    .from(auditRecords)
    .where(agentDid === undefined ? undefined : eq(auditRecords.agentDid, agentDid))
    .orderBy(asc(auditRecords.id));

  const records: string[] = [];
  for (const row of rows) {
    const principal =
      row.principalKind !== null && row.principalId !== null && row.principalName !== null
        ? { kind: row.principalKind, id: row.principalId, name: row.principalName }
        : undefined;
    const issued = await issueAuditRecord({
      record: {
        ...(row.agentDid === null ? {} : { agentDid: row.agentDid }),
        ...(principal === undefined ? {} : { principal }),
        // An agent action's chain is the agent; a control-plane action was
        // taken by its principal, not by any agent (see `AuditRecord`).
        authorityChain: principal === undefined && row.agentDid !== null ? [row.agentDid] : [],
        ...(row.tool === null ? {} : { tool: row.tool }),
        action: row.action,
        dataCategories: row.dataCategories,
        policy: { rule: row.policyRule, decision: row.decision as "allow" | "deny" },
        recordedAt: row.recordedAt.toISOString(),
        ...(row.reason === null ? {} : { reason: row.reason }),
      },
      signer,
    });
    if (!issued.ok) {
      return err({ code: "SIGNING_FAILED", reason: issued.error.reason });
    }
    records.push(issued.value);
  }

  return ok(records);
}

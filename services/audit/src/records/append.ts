import { asc, desc, eq, isNotNull, isNull, sql } from "drizzle-orm";
import {
  AUDIT_GENESIS_HASH,
  computeAuditEntryHash,
  computeAuditPayloadHash,
  serializeAuditRecord,
  type AuditPrincipal,
  type AuditRecord,
} from "@custos/core";
import type { AuditEvent } from "@custos/contracts";
import { auditRecords } from "../db/schema.js";
import type { AuditDb } from "../db/client.js";

// One lock for the whole chain: appends (and the one-off chaining of older
// rows) take it for the length of their transaction, so the head they read is
// still the head when they insert. The unique `seq` and `prev_hash` columns
// refuse a fork even if this were missing.
const LEDGER_LOCK_ID = 0x637573746f73; // "custos"

type Tx = Parameters<Parameters<AuditDb["transaction"]>[0]>[0];

async function lockLedger(tx: Tx): Promise<void> {
  await tx.execute(sql`select pg_advisory_xact_lock(${LEDGER_LOCK_ID})`);
}

async function headOf(tx: Tx): Promise<{ seq: number; hash: string }> {
  const [head] = await tx
    .select({ seq: auditRecords.seq, hash: auditRecords.hash })
    .from(auditRecords)
    .where(isNotNull(auditRecords.seq))
    .orderBy(desc(auditRecords.seq))
    .limit(1);
  return head === undefined
    ? { seq: 0, hash: AUDIT_GENESIS_HASH }
    : { seq: head.seq!, hash: head.hash! };
}

function chainFields(head: { seq: number; hash: string }, payload: string) {
  const seq = head.seq + 1;
  const payloadHash = computeAuditPayloadHash(payload);
  return {
    seq,
    prevHash: head.hash,
    payload,
    payloadHash,
    hash: computeAuditEntryHash({ seq, prevHash: head.hash, payloadHash }),
  };
}

/** An agent action's chain is the agent; a control-plane action was taken by its principal. */
function authorityChainOf(agentDid: string | undefined, principal: unknown): readonly string[] {
  return principal === undefined && agentDid !== undefined ? [agentDid] : [];
}

/**
 * Appends one reported event to the ledger (ADR 0017 §1): serialised once,
 * hashed, and linked to the head, inside one locked transaction. No network
 * call and no signature: sealing happens separately (`sealOnce`).
 * `reportedBy` is the authenticated caller, not anything in the event.
 */
export async function appendAuditRecord(params: {
  readonly db: AuditDb;
  readonly event: AuditEvent;
  readonly reportedBy: AuditPrincipal;
  readonly now: Date;
}): Promise<{ readonly seq: number }> {
  const { db, event, reportedBy, now } = params;
  const record: AuditRecord = {
    ...(event.agentDid === undefined ? {} : { agentDid: event.agentDid }),
    ...(event.principal === undefined ? {} : { principal: event.principal }),
    authorityChain: authorityChainOf(event.agentDid, event.principal),
    ...(event.tool === undefined ? {} : { tool: event.tool }),
    action: event.action,
    dataCategories: event.dataCategories,
    policy: event.policy,
    ...(event.reason === undefined ? {} : { reason: event.reason }),
    recordedAt: now.toISOString(),
    reportedBy,
  };
  const payload = serializeAuditRecord(record);

  return db.transaction(async (tx) => {
    await lockLedger(tx);
    const chained = chainFields(await headOf(tx), payload);
    await tx.insert(auditRecords).values({
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
      reportedByKind: reportedBy.kind,
      reportedById: reportedBy.id,
      reportedByName: reportedBy.name,
      ...chained,
    });
    return { seq: chained.seq };
  });
}

/**
 * Chains rows stored before the ledger existed, once, in the order they were
 * stored (ADR 0017 §5). Their payload is serialised from the columns now and
 * stored, so it is never rebuilt again; they have no `reportedBy`. Returns how
 * many rows were chained.
 */
export async function chainUnchainedRecords(db: AuditDb): Promise<number> {
  return db.transaction(async (tx) => {
    await lockLedger(tx);
    const rows = await tx
      .select()
      .from(auditRecords)
      .where(isNull(auditRecords.seq))
      .orderBy(asc(auditRecords.id));
    let head = await headOf(tx);
    for (const row of rows) {
      const principal =
        row.principalKind !== null && row.principalId !== null && row.principalName !== null
          ? { kind: row.principalKind, id: row.principalId, name: row.principalName }
          : undefined;
      const record: AuditRecord = {
        ...(row.agentDid === null ? {} : { agentDid: row.agentDid }),
        ...(principal === undefined ? {} : { principal }),
        authorityChain: authorityChainOf(row.agentDid ?? undefined, principal),
        ...(row.tool === null ? {} : { tool: row.tool }),
        action: row.action,
        dataCategories: row.dataCategories,
        policy: { rule: row.policyRule, decision: row.decision as "allow" | "deny" },
        recordedAt: row.recordedAt.toISOString(),
        ...(row.reason === null ? {} : { reason: row.reason }),
      };
      const chained = chainFields(head, serializeAuditRecord(record));
      await tx.update(auditRecords).set(chained).where(eq(auditRecords.id, row.id));
      head = chained;
    }
    return rows.length;
  });
}

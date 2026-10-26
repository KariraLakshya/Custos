import { asc, isNotNull } from "drizzle-orm";
import type { ServedAuditEntry } from "@custos/core";
import { auditRecords } from "../db/schema.js";
import type { AuditDb } from "../db/client.js";

/**
 * The ledger as served (ADR 0017 §5): every chained entry in order, exactly as
 * stored. Nothing is signed here; a reader checks the chain against a seal.
 * With `agentDid`, other agents' entries are served as their hashes only, so
 * one agent's entries can be checked without the others' contents. That is a
 * verification property, not privacy: without `agentDid` everything is served
 * (ADR 0008 decision 3).
 */
export async function listAuditEntries(params: {
  readonly db: AuditDb;
  readonly agentDid?: string;
}): Promise<readonly ServedAuditEntry[]> {
  const { db, agentDid } = params;
  const rows = await db
    .select({
      seq: auditRecords.seq,
      agentDid: auditRecords.agentDid,
      payload: auditRecords.payload,
      payloadHash: auditRecords.payloadHash,
    })
    .from(auditRecords)
    .where(isNotNull(auditRecords.seq))
    .orderBy(asc(auditRecords.seq));

  return rows.map((row) => {
    // Non-null by the query: every column of the chain is set together.
    const entry = { seq: row.seq!, payloadHash: row.payloadHash! };
    return agentDid === undefined || row.agentDid === agentDid
      ? { ...entry, payload: row.payload! }
      : entry;
  });
}

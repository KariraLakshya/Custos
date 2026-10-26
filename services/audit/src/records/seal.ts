import { desc, isNotNull } from "drizzle-orm";
import { issueAuditSeal, type AuditSealSigner } from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { auditRecords, auditSeals } from "../db/schema.js";
import type { AuditDb } from "../db/client.js";

export type SealError = { readonly code: "SIGNING_FAILED"; readonly reason: string };

/** The newest stored seal, as signed; null before the first. */
export async function latestSeal(db: AuditDb): Promise<string | null> {
  const [row] = await db
    .select({ seal: auditSeals.seal })
    .from(auditSeals)
    .orderBy(desc(auditSeals.seq))
    .limit(1);
  return row?.seal ?? null;
}

/**
 * Seals the head if it has moved since the last seal (ADR 0017 §2): one
 * signature, whatever the traffic, and never on the append path. Returns the
 * sealed `seq`, or null when there was nothing new. A signing failure (KMS
 * unreachable) is returned, not thrown; appends carry on and the next call
 * tries again. Two sealers racing store one seal per `seq`.
 */
export async function sealOnce(params: {
  readonly db: AuditDb;
  readonly signer: AuditSealSigner;
  readonly log: string;
  readonly now: Date;
}): Promise<Result<number | null, SealError>> {
  const { db, signer, log, now } = params;
  const [head] = await db
    .select({ seq: auditRecords.seq, hash: auditRecords.hash })
    .from(auditRecords)
    .where(isNotNull(auditRecords.seq))
    .orderBy(desc(auditRecords.seq))
    .limit(1);
  if (head === undefined) return ok(null);
  const [last] = await db
    .select({ seq: auditSeals.seq })
    .from(auditSeals)
    .orderBy(desc(auditSeals.seq))
    .limit(1);
  if (last !== undefined && last.seq >= head.seq!) return ok(null);

  const issued = await issueAuditSeal({
    seal: { log, seq: head.seq!, headHash: head.hash!, sealedAt: now.toISOString() },
    signer,
  });
  if (!issued.ok) return err(issued.error);
  await db
    .insert(auditSeals)
    .values({ seq: head.seq!, headHash: head.hash!, seal: issued.value, sealedAt: now })
    .onConflictDoNothing();
  return ok(head.seq!);
}

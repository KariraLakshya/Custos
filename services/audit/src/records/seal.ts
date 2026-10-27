import { asc, desc, eq, isNotNull, isNull } from "drizzle-orm";
import type { SealStore } from "@custos/audit-client";
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

export type CopyError = { readonly code: "COPY_FAILED"; readonly reason: string };

/**
 * Copies every stored seal not yet copied to the seal store, oldest first
 * (ADR 0017 part 2a), and records each success. Stops at the first failure,
 * which is returned, not thrown: the store being down must never hold up
 * appends or sealing, and the next call tries again from the same seal. A
 * conflict (another seal already stored at that position) is a failure too,
 * and stays one until a person looks.
 */
export async function copySeals(params: {
  readonly db: AuditDb;
  readonly store: SealStore;
  readonly log: string;
  readonly now: Date;
}): Promise<Result<number, CopyError>> {
  const { db, store, log, now } = params;
  const pending = await db
    .select({ seq: auditSeals.seq, seal: auditSeals.seal })
    .from(auditSeals)
    .where(isNull(auditSeals.pushedAt))
    .orderBy(asc(auditSeals.seq));
  let copied = 0;
  for (const row of pending) {
    try {
      await store.put({ log, seq: row.seq, seal: row.seal });
    } catch (error) {
      return err({
        code: "COPY_FAILED",
        reason: error instanceof Error ? error.message : String(error),
      });
    }
    await db.update(auditSeals).set({ pushedAt: now }).where(eq(auditSeals.seq, row.seq));
    copied += 1;
  }
  return ok(copied);
}

/** How far sealing and copying have got (ADR 0017 part 2a), for `GET /seals/status`. */
export async function sealStatus(db: AuditDb): Promise<{
  readonly sealedThrough: number;
  readonly copiedThrough: number;
  readonly oldestUncopiedSealedAt: string | null;
}> {
  const [sealed] = await db
    .select({ seq: auditSeals.seq })
    .from(auditSeals)
    .orderBy(desc(auditSeals.seq))
    .limit(1);
  const [copied] = await db
    .select({ seq: auditSeals.seq })
    .from(auditSeals)
    .where(isNotNull(auditSeals.pushedAt))
    .orderBy(desc(auditSeals.seq))
    .limit(1);
  const [oldest] = await db
    .select({ sealedAt: auditSeals.sealedAt })
    .from(auditSeals)
    .where(isNull(auditSeals.pushedAt))
    .orderBy(asc(auditSeals.seq))
    .limit(1);
  return {
    sealedThrough: sealed?.seq ?? 0,
    copiedThrough: copied?.seq ?? 0,
    oldestUncopiedSealedAt: oldest?.sealedAt.toISOString() ?? null,
  };
}

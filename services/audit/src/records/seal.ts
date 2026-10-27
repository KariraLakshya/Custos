import { asc, desc, eq, isNotNull, isNull } from "drizzle-orm";
import { SealCopyConflictError, type SealStore } from "@custos/audit-client";
import { issueAuditSeal, verifyAuditSeal, type AuditSealSigner } from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { auditRecords, auditSeals } from "../db/schema.js";
import type { AuditDb } from "../db/client.js";

export type SealError = { readonly code: "SIGNING_FAILED"; readonly reason: string };

/**
 * The newest stored seal made by `key`, as signed; null when there is none.
 * After a key rotation that is null until the head moves and a new seal is
 * made: older seals stay stored, checked by auditors under the old key.
 */
export async function latestSeal(db: AuditDb, key: string): Promise<string | null> {
  const [row] = await db
    .select({ seal: auditSeals.seal })
    .from(auditSeals)
    .where(eq(auditSeals.signingKey, key))
    .orderBy(desc(auditSeals.seq))
    .limit(1);
  return row?.seal ?? null;
}

/**
 * Seals the head if it has moved since the last seal (ADR 0017 §2): one
 * signature, whatever the traffic, and never on the append path. Returns the
 * sealed `seq`, or null when there was nothing new. A signing failure (KMS
 * unreachable) is returned, not thrown; appends carry on and the next call
 * tries again. Two sealers racing store one seal per `seq`. A position
 * already sealed is never sealed again under a new key: that would make an
 * honest rotation look like a rewrite to the seal store.
 */
export async function sealOnce(params: {
  readonly db: AuditDb;
  readonly signer: AuditSealSigner;
  readonly log: string;
  /** The signing key's public half, multibase; named inside the seal. */
  readonly key: string;
  readonly now: Date;
}): Promise<Result<number | null, SealError>> {
  const { db, signer, log, key, now } = params;
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
    seal: { log, seq: head.seq!, headHash: head.hash!, key, sealedAt: now.toISOString() },
    signer,
  });
  if (!issued.ok) return err(issued.error);
  await db
    .insert(auditSeals)
    .values({
      seq: head.seq!,
      headHash: head.hash!,
      seal: issued.value,
      signingKey: key,
      sealedAt: now,
    })
    .onConflictDoNothing();
  return ok(head.seq!);
}

export type CopyError = {
  /** SEAL_CONFLICT: a different seal is already stored at that position (evidence of a rewrite). */
  readonly code: "COPY_FAILED" | "SEAL_CONFLICT";
  readonly reason: string;
};

/**
 * Whether each stored seal verifies under the current key, remembered so each
 * seal's signature is checked once, not on every tick or status request: the
 * status route is open, and Ed25519 verification blocks the event loop.
 */
export interface CopyVerdicts {
  check(seq: number, seal: string): { readonly copyable: boolean; readonly fresh: boolean };
  /** Seals checked and found not to verify under the current key. */
  notCopyable(): ReadonlySet<number>;
}

export function createCopyVerdicts(params: {
  readonly log: string;
  readonly key: string;
  /** Injectable for tests. */
  readonly verify?: typeof verifyAuditSeal;
}): CopyVerdicts {
  const verify = params.verify ?? verifyAuditSeal;
  const known = new Map<string, boolean>();
  const bad = new Set<number>();
  return {
    check(seq, seal) {
      const id = `${seq}:${seal}`;
      const cached = known.get(id);
      if (cached !== undefined) return { copyable: cached, fresh: false };
      const copyable = verify({ seal, trustedKeys: [params.key], log: params.log }).ok;
      known.set(id, copyable);
      if (!copyable) bad.add(seq);
      return { copyable, fresh: true };
    },
    notCopyable: () => bad,
  };
}

// A backlog after a long outage is thousands of seals: yield now and then so
// verifying them never holds up appends for long.
const VERIFY_BATCH = 50;

/**
 * Copies every stored seal not yet copied to the seal store, oldest first
 * (ADR 0017 part 2a), and records each success. Stops at the first failure,
 * which is returned, not thrown: the store being down must never hold up
 * appends or sealing, and the next call tries again from the same seal. A
 * conflict (another seal already stored at that position) is a failure too,
 * and stays one until a person looks.
 *
 * Only seals that verify under the **current** key are copied, checked by
 * signature, not by the `signing_key` column, which anyone with access to
 * this database could set. The store cannot be cleaned, so one bad copy would
 * fail every auditor for good. The rest are skipped and listed by
 * `sealStatus`; seals made under an earlier key and not copied before the
 * rotation stay uncopied.
 */
export async function copySeals(params: {
  readonly db: AuditDb;
  readonly store: SealStore;
  readonly log: string;
  readonly verdicts: CopyVerdicts;
  readonly now: Date;
}): Promise<Result<number, CopyError>> {
  const { db, store, log, verdicts, now } = params;
  const pending = await db
    .select({ seq: auditSeals.seq, seal: auditSeals.seal })
    .from(auditSeals)
    .where(isNull(auditSeals.pushedAt))
    .orderBy(asc(auditSeals.seq));
  let copied = 0;
  let checked = 0;
  for (const row of pending) {
    const verdict = verdicts.check(row.seq, row.seal);
    if (verdict.fresh && (checked += 1) % VERIFY_BATCH === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    if (!verdict.copyable) continue;
    try {
      await store.put({ log, seq: row.seq, seal: row.seal });
    } catch (error) {
      return err({
        code: error instanceof SealCopyConflictError ? "SEAL_CONFLICT" : "COPY_FAILED",
        reason: error instanceof Error ? error.message : String(error),
      });
    }
    await db.update(auditSeals).set({ pushedAt: now }).where(eq(auditSeals.seq, row.seq));
    copied += 1;
  }
  return ok(copied);
}

/**
 * How far sealing and copying have got (ADR 0017 part 2a), for the open
 * `GET /seals/status`. Verifies nothing: `notCopyable` comes from the verdicts
 * copying has already reached.
 */
export async function sealStatus(
  db: AuditDb,
  verdicts: CopyVerdicts,
): Promise<{
  readonly sealedThrough: number;
  readonly copiedThrough: number;
  readonly oldestUncopiedSealedAt: string | null;
  /** Uncopied seals found not to verify under the current key: never copied. */
  readonly notCopyable: readonly number[];
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
  const uncopied = await db
    .select({ seq: auditSeals.seq, sealedAt: auditSeals.sealedAt })
    .from(auditSeals)
    .where(isNull(auditSeals.pushedAt))
    .orderBy(asc(auditSeals.seq));
  const bad = verdicts.notCopyable();
  const oldest = uncopied.find((row) => !bad.has(row.seq));
  return {
    sealedThrough: sealed?.seq ?? 0,
    copiedThrough: copied?.seq ?? 0,
    oldestUncopiedSealedAt: oldest?.sealedAt.toISOString() ?? null,
    notCopyable: uncopied.filter((row) => bad.has(row.seq)).map((row) => row.seq),
  };
}

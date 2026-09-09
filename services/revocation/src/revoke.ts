import { eq, isNotNull } from "drizzle-orm";
import { issueRevocationTombstone, type TombstoneSigner } from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { statusListEntries, type StatusListEntryRow } from "./db/schema.js";
import type { RevocationDb } from "./db/client.js";
import type { BroadcastOutcome, TombstoneBroadcaster } from "./broadcast.js";

export type RevokeAgentError =
  | { readonly code: "UNKNOWN_AGENT"; readonly agentId: string }
  | { readonly code: "SIGNING_FAILED"; readonly reason: string };

export interface RevokedAgent {
  readonly agentId: string;
  readonly agentDid: string;
  readonly statusListIndex: number;
  readonly revokedAt: string;
  readonly alreadyRevoked: boolean;
  readonly broadcast: BroadcastOutcome;
}

async function findByAgentId(
  db: RevocationDb,
  agentId: string,
): Promise<StatusListEntryRow | undefined> {
  const rows = await db
    .select()
    .from(statusListEntries)
    .where(eq(statusListEntries.agentId, agentId))
    .limit(1);
  return rows[0];
}

/**
 * Flips the agent's status list bit, then signs and pushes a tombstone to
 * every subscriber. The database write happens first: a revocation that is
 * durably recorded but not yet delivered converges on the next subscriber
 * resync, whereas one that is broadcast but not recorded would silently
 * un-revoke itself the moment a subscriber restarts.
 *
 * Idempotent. Re-revoking an already-revoked agent keeps the original
 * `revokedAt` (the moment access was actually withdrawn is a fact, not
 * something a retry should rewrite) but re-broadcasts, which is how an
 * operator can force redelivery to a subscriber that was down.
 */
export async function revokeAgent(params: {
  readonly db: RevocationDb;
  readonly broadcaster: TombstoneBroadcaster;
  readonly signer: TombstoneSigner;
  readonly agentId: string;
  readonly reason?: string;
  readonly now: Date;
}): Promise<Result<RevokedAgent, RevokeAgentError>> {
  const { db, broadcaster, signer, agentId, reason, now } = params;

  const existing = await findByAgentId(db, agentId);
  if (!existing) {
    return err({ code: "UNKNOWN_AGENT", agentId });
  }

  const alreadyRevoked = existing.revokedAt !== null;
  const revokedAt = existing.revokedAt ?? now;

  if (!alreadyRevoked) {
    await db
      .update(statusListEntries)
      .set({ revokedAt, reason: reason ?? null })
      .where(eq(statusListEntries.agentDid, existing.agentDid));
  }

  const tombstone = await issueRevocationTombstone({
    tombstone: {
      agentDid: existing.agentDid,
      statusListIndex: existing.statusListIndex,
      revokedAt: revokedAt.toISOString(),
      ...(reason === undefined ? {} : { reason }),
    },
    signer,
  });
  if (!tombstone.ok) {
    return err({ code: "SIGNING_FAILED", reason: tombstone.error.reason });
  }

  return ok({
    agentId,
    agentDid: existing.agentDid,
    statusListIndex: existing.statusListIndex,
    revokedAt: revokedAt.toISOString(),
    alreadyRevoked,
    broadcast: await broadcaster.broadcast(tombstone.value),
  });
}

/**
 * Every revocation as a freshly signed tombstone, for a subscriber
 * bootstrapping its local cache at boot or catching up after a missed push.
 * Re-signed rather than stored so there is exactly one tombstone format and
 * one verification path in the system.
 */
export async function listTombstones(params: {
  readonly db: RevocationDb;
  readonly signer: TombstoneSigner;
}): Promise<Result<readonly string[], RevokeAgentError>> {
  const { db, signer } = params;

  const rows = await db
    .select()
    .from(statusListEntries)
    .where(isNotNull(statusListEntries.revokedAt));

  const tombstones: string[] = [];
  for (const row of rows) {
    const issued = await issueRevocationTombstone({
      tombstone: {
        agentDid: row.agentDid,
        statusListIndex: row.statusListIndex,
        // `revokedAt` is non-null by the query above.
        revokedAt: row.revokedAt!.toISOString(),
        ...(row.reason === null ? {} : { reason: row.reason }),
      },
      signer,
    });
    if (!issued.ok) {
      return err({ code: "SIGNING_FAILED", reason: issued.error.reason });
    }
    tombstones.push(issued.value);
  }

  return ok(tombstones);
}

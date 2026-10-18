import { inArray } from "drizzle-orm";
import {
  applyStatusList,
  revokedIndexes,
  verifyForeignStatusList,
  type StatusAnchor,
  type VerifiedForeignStatusList,
} from "@custos/core";
import { controlPlaneEvent } from "@custos/audit-client";
import { err, ok, type AuditEvent, type AuditPrincipal, type Result } from "@custos/contracts";
import { externalRevokedIndexes, statusListEntries } from "../db/schema.js";
import type { RevocationDb } from "../db/client.js";
import type { RevokedAgent, RevokeAgentError } from "../revoke.js";

/**
 * Brings revocations made through the publisher into this service's own state
 * (ADR 0014 "Fix 1", decision recorded in its Open questions). Revocation is
 * permanent, so two copies of the list always merge by union: every bit set in
 * the published list is set here, and none is ever cleared.
 *
 * While this feature is on, the service answers "who is revoked" only when the
 * newest published list it has verified is still inside its window
 * (`isOpen`); otherwise it cannot claim an agent is not revoked.
 */

export const PUBLISHED_LIST_REASON = "published-list";
const PRINCIPAL: AuditPrincipal = {
  kind: "service",
  id: "revocation-reconciler",
  name: "revocation service (published-list merge)",
};
// Queries take the indexes in batches so a large list stays within parameter limits.
const BATCH = 1_000;
// A published list is at most about 16 MiB raw and compresses well; this bounds the body read.
const MAX_BODY_CHARS = 2_097_152;

export type ReconcileError =
  | { readonly code: "FETCH_FAILED"; readonly reason: string }
  | { readonly code: "LIST_REJECTED"; readonly reason: string }
  | { readonly code: "MERGE_INCOMPLETE"; readonly failed: number }
  /** A tick was skipped because the previous merge is still running; not a failure. */
  | { readonly code: "ALREADY_RUNNING" };

export interface ReconcileOutcome {
  /** Agents revoked here because the published list had their bit. */
  readonly revokedAgents: number;
  /** Bits for which this database has no agent row, kept by index. */
  readonly storedByIndex: number;
  /** True when the list was inside its window and so reopens (or extends) the gate. */
  readonly confirmed: boolean;
}

export interface PublishedListReconciler {
  reconcileOnce(now: Date): Promise<Result<ReconcileOutcome, ReconcileError>>;
  /** True only while the newest confirmed published list is inside its window. */
  isOpen(now: Date): boolean;
  /** For `/health`: no secrets, only whether and until when the gate is open. */
  status(now: Date): { readonly open: boolean; readonly confirmedUntil: string | null };
  start(intervalMs: number, now: () => Date, onError: (error: ReconcileError) => void): void;
  stop(): void;
}

/** GET with a timeout, a status check and a body cap, then parsed as JSON. */
export function createHttpListFetcher(params: {
  readonly url: string;
  readonly timeoutMs: number;
  readonly fetchImpl?: typeof fetch;
}): () => Promise<unknown> {
  const fetchImpl = params.fetchImpl ?? fetch;
  return async () => {
    const response = await fetchImpl(params.url, { signal: AbortSignal.timeout(params.timeoutMs) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const text = await response.text();
    if (text.length > MAX_BODY_CHARS) throw new Error("response body too large");
    return JSON.parse(text) as unknown;
  };
}

export function createPublishedListReconciler(params: {
  readonly db: RevocationDb;
  /** This service's own status key and list identity, with the freshness window. */
  readonly anchor: StatusAnchor;
  readonly fetchList: () => Promise<unknown>;
  readonly maxClockSkewSeconds: number;
  /** Revokes a known agent (flips its row, signs and pushes a tombstone). */
  readonly revoke: (
    agentId: string,
    reason: string,
    now: Date,
  ) => Promise<Result<RevokedAgent, RevokeAgentError>>;
  readonly report: (event: AuditEvent) => void;
}): PublishedListReconciler {
  const { db, anchor } = params;
  let view: VerifiedForeignStatusList | undefined;
  let running = false;
  let timer: ReturnType<typeof setInterval> | undefined;

  async function entriesFor(indexes: readonly number[]) {
    const found = new Map<number, { agentId: string; agentDid: string; revoked: boolean }>();
    for (let i = 0; i < indexes.length; i += BATCH) {
      const batch = indexes.slice(i, i + BATCH);
      const rows = await db
        .select({
          index: statusListEntries.statusListIndex,
          agentId: statusListEntries.agentId,
          agentDid: statusListEntries.agentDid,
          revokedAt: statusListEntries.revokedAt,
        })
        .from(statusListEntries)
        .where(inArray(statusListEntries.statusListIndex, batch));
      for (const row of rows) {
        found.set(row.index, {
          agentId: row.agentId,
          agentDid: row.agentDid,
          revoked: row.revokedAt !== null,
        });
      }
    }
    return found;
  }

  async function storedIndexes(indexes: readonly number[]): Promise<Set<number>> {
    const stored = new Set<number>();
    for (let i = 0; i < indexes.length; i += BATCH) {
      const rows = await db
        .select({ index: externalRevokedIndexes.statusListIndex })
        .from(externalRevokedIndexes)
        .where(inArray(externalRevokedIndexes.statusListIndex, indexes.slice(i, i + BATCH)));
      for (const row of rows) stored.add(row.index);
    }
    return stored;
  }

  async function reconcileOnce(now: Date): Promise<Result<ReconcileOutcome, ReconcileError>> {
    let raw: unknown;
    try {
      raw = await params.fetchList();
    } catch (error) {
      return err({
        code: "FETCH_FAILED",
        reason: error instanceof Error ? error.message : String(error),
      });
    }

    // A stale list is still merged: its bits are true because a revocation is
    // permanent. Only a list inside its window reopens the gate.
    const verified = await verifyForeignStatusList({
      credential: raw,
      anchor,
      now,
      maxClockSkewSeconds: params.maxClockSkewSeconds,
      acceptStale: true,
    });
    if (!verified.ok) return err({ code: "LIST_REJECTED", reason: verified.error.code });

    const indexes = revokedIndexes(verified.value.list);
    const entries = await entriesFor(indexes);
    const alreadyStored = await storedIndexes(indexes.filter((index) => !entries.has(index)));

    // Only bits that are new here are acted on: revoking again would re-push
    // every tombstone ever issued on each poll.
    let revokedAgents = 0;
    let storedByIndex = 0;
    let failed = 0;
    for (const index of indexes) {
      const entry = entries.get(index);
      if (entry !== undefined) {
        if (entry.revoked) continue;
        const revoked = await params.revoke(entry.agentId, PUBLISHED_LIST_REASON, now);
        if (!revoked.ok) {
          failed += 1;
          continue;
        }
        // Revoked by someone else between our read and this call: not ours to count or audit.
        if (revoked.value.alreadyRevoked) continue;
        revokedAgents += 1;
        params.report(
          controlPlaneEvent({
            principal: PRINCIPAL,
            scope: "reconcile:published-list",
            action: "agents.revoke",
            decision: "allow",
            agentDid: entry.agentDid,
            reason: PUBLISHED_LIST_REASON,
          }),
        );
        continue;
      }
      if (alreadyStored.has(index)) continue;
      await db
        .insert(externalRevokedIndexes)
        .values({ statusListIndex: index, firstSeenInListAt: verified.value.validFrom })
        .onConflictDoNothing();
      storedByIndex += 1;
      params.report(
        controlPlaneEvent({
          principal: PRINCIPAL,
          scope: "reconcile:published-list",
          action: "agents.revoke",
          decision: "allow",
          reason: `${PUBLISHED_LIST_REASON}: status list index ${index}`,
        }),
      );
    }

    // The gate reopens only after every revocation has been applied.
    if (failed > 0) return err({ code: "MERGE_INCOMPLETE", failed });
    const confirmed = now.getTime() < verified.value.notAfter.getTime();
    if (confirmed) view = applyStatusList(view, verified.value);
    return ok({ revokedAgents, storedByIndex, confirmed });
  }

  return {
    async reconcileOnce(now) {
      // One merge at a time: a slow one must not be overtaken by the next tick.
      if (running) return err({ code: "ALREADY_RUNNING" });
      running = true;
      try {
        return await reconcileOnce(now);
      } finally {
        running = false;
      }
    },
    isOpen(now) {
      return view !== undefined && now.getTime() < view.notAfter.getTime();
    },
    status(now) {
      const open = view !== undefined && now.getTime() < view.notAfter.getTime();
      return { open, confirmedUntil: view === undefined ? null : view.notAfter.toISOString() };
    },
    start(intervalMs, now, onError) {
      if (timer !== undefined) return;
      const tick = (): void => {
        void this.reconcileOnce(now()).then((result) => {
          if (!result.ok && result.error.code !== "ALREADY_RUNNING") onError(result.error);
        });
      };
      tick();
      timer = setInterval(tick, intervalMs);
      timer.unref();
    },
    stop() {
      if (timer !== undefined) clearInterval(timer);
      timer = undefined;
    },
  };
}

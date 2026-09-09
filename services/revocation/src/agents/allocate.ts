import { eq } from "drizzle-orm";
import { err, ok, type Result } from "@custos/contracts";
import { statusListEntries } from "../db/schema.js";
import type { RevocationDb } from "../db/client.js";

export type AllocateIndexError = { readonly code: "ALLOCATION_FAILED"; readonly reason: string };

export interface AllocatedStatusListEntry {
  readonly agentDid: string;
  readonly statusListIndex: number;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Reserves this agent's single bit in the published status list. Called by
 * the identity service *before* it issues the agent's credential, so the
 * index can be embedded in the credential's `credentialStatus`.
 *
 * Idempotent: re-allocating for a DID that already holds an index returns
 * the existing one rather than burning a second bit, so a retried
 * registration cannot leave an orphaned index behind.
 */
export async function allocateStatusListIndex(params: {
  readonly db: RevocationDb;
  readonly agentId: string;
  readonly agentDid: string;
}): Promise<Result<AllocatedStatusListEntry, AllocateIndexError>> {
  const { db, agentId, agentDid } = params;

  try {
    const inserted = await db
      .insert(statusListEntries)
      .values({ agentId, agentDid })
      .onConflictDoNothing()
      .returning({ statusListIndex: statusListEntries.statusListIndex });

    const allocated = inserted[0];
    if (allocated) {
      return ok({ agentDid, statusListIndex: allocated.statusListIndex });
    }

    const existing = await db
      .select({ statusListIndex: statusListEntries.statusListIndex })
      .from(statusListEntries)
      .where(eq(statusListEntries.agentDid, agentDid))
      .limit(1);

    const row = existing[0];
    if (!row) {
      return err({ code: "ALLOCATION_FAILED", reason: "index neither inserted nor found" });
    }
    return ok({ agentDid, statusListIndex: row.statusListIndex });
  } catch (error) {
    return err({ code: "ALLOCATION_FAILED", reason: errorMessage(error) });
  }
}

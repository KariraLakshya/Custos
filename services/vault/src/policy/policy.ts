import { and, eq } from "drizzle-orm";
import { agentPolicies } from "../db/schema.js";
import type { VaultDb } from "../db/client.js";

/**
 * Simple per-agent × tool allowlist (build plan Phase 4 — "not full
 * OPA/Rego"). Absence of a grant means denied: fail closed, deny by
 * default, the same posture as every other security decision here.
 */
export async function isToolAllowed(db: VaultDb, agentDid: string, tool: string): Promise<boolean> {
  const [row] = await db
    .select({ tool: agentPolicies.tool })
    .from(agentPolicies)
    .where(and(eq(agentPolicies.agentDid, agentDid), eq(agentPolicies.tool, tool)))
    .limit(1);
  return row !== undefined;
}

/** Grants `agentDid` access to `tool`. Idempotent — granting twice is a no-op. */
export async function grantToolAccess(db: VaultDb, agentDid: string, tool: string): Promise<void> {
  await db
    .insert(agentPolicies)
    .values({ agentDid, tool })
    .onConflictDoNothing({ target: [agentPolicies.agentDid, agentPolicies.tool] });
}

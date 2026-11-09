import { and, eq } from "drizzle-orm";
import { agentPolicies } from "../db/schema.js";
import type { VaultDb } from "../db/client.js";

/** The principal that made a grant (ADR 0020 §1), as `principalOf` gave it. */
export interface GrantedBy {
  readonly kind: "operator" | "service";
  readonly id: string;
  readonly name: string;
  readonly via?: "custos-admin" | "sso";
}

/**
 * Simple per-agent × tool allowlist (build plan Phase 4 — "not full
 * OPA/Rego"). Absence of a grant means denied: fail closed, deny by
 * default, the same posture as every other security decision here.
 * A grant with no recorded granter still counts for the agent itself.
 */
export async function isToolAllowed(db: VaultDb, agentDid: string, tool: string): Promise<boolean> {
  const [row] = await db
    .select({ tool: agentPolicies.tool })
    .from(agentPolicies)
    .where(and(eq(agentPolicies.agentDid, agentDid), eq(agentPolicies.tool, tool)))
    .limit(1);
  return row !== undefined;
}

/**
 * Grants `agentDid` access to `tool`, recording who granted it. Granting
 * again keeps the row and records the newer granter.
 */
export async function grantToolAccess(
  db: VaultDb,
  agentDid: string,
  tool: string,
  grantedBy: GrantedBy,
): Promise<void> {
  const granter = {
    grantedByKind: grantedBy.kind,
    grantedById: grantedBy.id,
    grantedByName: grantedBy.name,
    grantedByVia: grantedBy.via ?? null,
  };
  await db
    .insert(agentPolicies)
    .values({ agentDid, tool, ...granter })
    .onConflictDoUpdate({ target: [agentPolicies.agentDid, agentPolicies.tool], set: granter });
}

/**
 * The grant a delegation chain may start from (ADR 0020 §1): one made by an
 * operator. Null when there is no grant, when it predates `granted_by`, or
 * when a service made it — a chain never starts from an unknown authority.
 */
export async function rootGrantOf(
  db: VaultDb,
  agentDid: string,
  tool: string,
): Promise<GrantedBy | null> {
  const [row] = await db
    .select({
      kind: agentPolicies.grantedByKind,
      id: agentPolicies.grantedById,
      name: agentPolicies.grantedByName,
      via: agentPolicies.grantedByVia,
    })
    .from(agentPolicies)
    .where(and(eq(agentPolicies.agentDid, agentDid), eq(agentPolicies.tool, tool)))
    .limit(1);
  if (row?.kind !== "operator" || row.id === null || row.name === null) return null;
  return { kind: "operator", id: row.id, name: row.name, ...(row.via ? { via: row.via } : {}) };
}

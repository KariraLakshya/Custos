import { and, asc, eq, sql, type SQL } from "drizzle-orm";
import { agentPolicies } from "../db/schema.js";
import type { VaultDb } from "../db/client.js";
import type { GrantedBy } from "./policy.js";

/** One grant as `GET /policies` shows it (ADR 0022 §1). Never a tool credential. */
export interface ListedGrant {
  readonly agentDid: string;
  readonly tool: string;
  /** Null for grants made before migration 0013. */
  readonly grantedBy: GrantedBy | null;
  readonly createdAt: string;
}

export interface GrantPage {
  readonly grants: readonly ListedGrant[];
  /** Pass as `cursor` for the next page; null on the last one. */
  readonly nextCursor: string | null;
}

/** Where a page ends: the last grant's key, `(agent DID, tool)`. */
interface GrantCursor {
  readonly agentDid: string;
  readonly tool: string;
}

const CURSOR_MAX_LENGTH = 4096;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

export function encodeGrantCursor(cursor: GrantCursor): string {
  return Buffer.from(JSON.stringify([cursor.agentDid, cursor.tool]), "utf8").toString("base64url");
}

/** Untrusted input: anything but a cursor this service made is null, never thrown. */
export function decodeGrantCursor(value: string): GrantCursor | null {
  if (value.length > CURSOR_MAX_LENGTH || !BASE64URL.test(value)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 2 ||
    typeof parsed[0] !== "string" ||
    typeof parsed[1] !== "string" ||
    parsed[0] === "" ||
    parsed[1] === ""
  ) {
    return null;
  }
  return { agentDid: parsed[0], tool: parsed[1] };
}

/**
 * A page of grants, ordered by their primary key `(agent DID, tool)`, so a
 * page edge never skips or repeats one. Reads `agent_policies` only: tool
 * credentials live in another table and are never selected here.
 */
export async function listGrants(
  db: VaultDb,
  query: { readonly agentDid?: string; readonly after?: GrantCursor; readonly limit: number },
): Promise<GrantPage> {
  const conditions: SQL[] = [];
  if (query.agentDid !== undefined) conditions.push(eq(agentPolicies.agentDid, query.agentDid));
  if (query.after !== undefined) {
    conditions.push(
      sql`(${agentPolicies.agentDid}, ${agentPolicies.tool}) > (${query.after.agentDid}, ${query.after.tool})`,
    );
  }
  const rows = await db
    .select({
      agentDid: agentPolicies.agentDid,
      tool: agentPolicies.tool,
      createdAt: agentPolicies.createdAt,
      byKind: agentPolicies.grantedByKind,
      byId: agentPolicies.grantedById,
      byName: agentPolicies.grantedByName,
      byVia: agentPolicies.grantedByVia,
    })
    .from(agentPolicies)
    .where(and(...conditions))
    .orderBy(asc(agentPolicies.agentDid), asc(agentPolicies.tool))
    .limit(query.limit + 1);

  const page = rows.slice(0, query.limit);
  const last = page.at(-1);
  return {
    grants: page.map((row) => ({
      agentDid: row.agentDid,
      tool: row.tool,
      grantedBy:
        row.byKind === null || row.byId === null || row.byName === null
          ? null
          : {
              kind: row.byKind,
              id: row.byId,
              name: row.byName,
              ...(row.byVia === null ? {} : { via: row.byVia }),
            },
      createdAt: row.createdAt.toISOString(),
    })),
    nextCursor:
      rows.length > query.limit && last !== undefined
        ? encodeGrantCursor({ agentDid: last.agentDid, tool: last.tool })
        : null,
  };
}

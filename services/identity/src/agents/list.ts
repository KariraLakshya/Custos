import { and, asc, eq, gt, type SQL } from "drizzle-orm";
import { agents } from "../db/schema.js";
import type { IdentityDb } from "../db/client.js";

/** One agent as `GET /agents` shows it (ADR 0022 §2): no key, credential or DID document. */
export interface ListedAgent {
  readonly id: string;
  readonly did: string;
  readonly name: string | null;
  readonly registeredAt: string;
  /** Null for agents registered before migration 0015. */
  readonly registeredBy: {
    readonly kind: "operator" | "service";
    readonly id: string;
    readonly name: string;
    readonly via?: "custos-admin" | "sso";
  } | null;
}

export interface AgentPage {
  readonly agents: readonly ListedAgent[];
  /** Pass as `cursor` for the next page; null on the last one. */
  readonly nextCursor: string | null;
}

/**
 * A page of agents, ordered by id. Paged on the primary key, not on the
 * registration time: a timestamp cursor read back through a JS `Date` loses
 * Postgres's microseconds, which would skip or repeat agents at a page edge.
 */
export async function listAgents(
  db: IdentityDb,
  query: {
    readonly id?: string;
    readonly did?: string;
    readonly cursor?: string;
    readonly limit: number;
  },
): Promise<AgentPage> {
  const conditions: SQL[] = [];
  if (query.id !== undefined) conditions.push(eq(agents.id, query.id));
  if (query.did !== undefined) conditions.push(eq(agents.did, query.did));
  if (query.cursor !== undefined) conditions.push(gt(agents.id, query.cursor));
  // Only the columns shown: the credential, DID document and key never leave here.
  const rows = await db
    .select({
      id: agents.id,
      did: agents.did,
      name: agents.name,
      createdAt: agents.createdAt,
      byKind: agents.registeredByKind,
      byId: agents.registeredById,
      byName: agents.registeredByName,
      byVia: agents.registeredByVia,
    })
    .from(agents)
    .where(and(...conditions))
    .orderBy(asc(agents.id))
    .limit(query.limit + 1);

  const page = rows.slice(0, query.limit);
  return {
    agents: page.map((row) => ({
      id: row.id,
      did: row.did,
      name: row.name,
      registeredAt: row.createdAt.toISOString(),
      registeredBy:
        row.byKind === null || row.byId === null || row.byName === null
          ? null
          : {
              kind: row.byKind,
              id: row.byId,
              name: row.byName,
              ...(row.byVia === null ? {} : { via: row.byVia }),
            },
    })),
    nextCursor: rows.length > query.limit ? (page.at(-1)?.id ?? null) : null,
  };
}

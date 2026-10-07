import { asc, eq } from "drizzle-orm";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import { generateApiKey } from "./api-key.js";
import { apiKeys, type ApiKeyRow } from "./schema.js";
import { isScope, scopeAllowedFor, type PrincipalKind, type Scope } from "./scopes.js";

/** What the authenticator needs: one lookup by key id. */
export interface ApiKeyLookup {
  findById(id: string): Promise<ApiKeyRow | null>;
}

/** A key as listed to an administrator — never its hash. */
export interface ApiKeySummary {
  readonly id: string;
  readonly kind: PrincipalKind;
  readonly name: string;
  readonly scopes: readonly string[];
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
  readonly createdVia: "custos-admin" | "sso";
}

export interface CreateApiKeyInput {
  readonly kind: PrincipalKind;
  readonly name: string;
  readonly scopes: readonly string[];
  readonly expiresAt: Date;
  readonly now: Date;
  /** Defaults to `custos-admin`. */
  readonly createdVia?: "custos-admin" | "sso";
  readonly randomBytes?: (length: number) => Uint8Array;
}

export type CreateApiKeyError =
  | { readonly code: "INVALID_NAME" }
  | { readonly code: "NO_SCOPES" }
  | { readonly code: "UNKNOWN_SCOPE"; readonly scope: string }
  | { readonly code: "SCOPE_NOT_ALLOWED"; readonly scope: Scope }
  | { readonly code: "EXPIRY_NOT_IN_FUTURE" };

export interface ApiKeyStore extends ApiKeyLookup {
  /** Returns the full key exactly once; only its hash is stored. */
  create(
    input: CreateApiKeyInput,
  ): Promise<
    | { readonly ok: true; readonly id: string; readonly token: string }
    | { readonly ok: false; readonly error: CreateApiKeyError }
  >;
  list(): Promise<readonly ApiKeySummary[]>;
  /** False if no such key. Revoking an already revoked key keeps the first `revokedAt`. */
  revoke(id: string, now: Date): Promise<boolean>;
}

export function validateNewKey(input: CreateApiKeyInput): CreateApiKeyError | null {
  if (input.name.trim().length === 0 || input.name.length > 100) return { code: "INVALID_NAME" };
  if (input.scopes.length === 0) return { code: "NO_SCOPES" };
  for (const scope of input.scopes) {
    if (!isScope(scope)) return { code: "UNKNOWN_SCOPE", scope };
    if (!scopeAllowedFor(input.kind, scope)) return { code: "SCOPE_NOT_ALLOWED", scope };
  }
  if (input.expiresAt.getTime() <= input.now.getTime()) return { code: "EXPIRY_NOT_IN_FUTURE" };
  return null;
}

// The table is shared by every service, each with its own drizzle schema
// object; the query builder only needs the `apiKeys` table itself.
export function createApiKeyStore<TSchema extends Record<string, unknown>>(
  db: NodePgDatabase<TSchema>,
): ApiKeyStore {
  return {
    async findById(id) {
      const rows = await db.select().from(apiKeys).where(eq(apiKeys.id, id)).limit(1);
      return rows[0] ?? null;
    },

    async create(input) {
      const error = validateNewKey(input);
      if (error) return { ok: false, error };
      const key = generateApiKey(input.kind, input.randomBytes);
      await db.insert(apiKeys).values({
        id: key.id,
        kind: input.kind,
        name: input.name,
        scopes: [...new Set(input.scopes)],
        secretHash: key.secretHash,
        createdAt: input.now,
        createdVia: input.createdVia ?? "custos-admin",
        expiresAt: input.expiresAt,
      });
      return { ok: true, id: key.id, token: key.token };
    },

    async list() {
      const rows = await db.select().from(apiKeys).orderBy(asc(apiKeys.createdAt));
      return rows.map(({ secretHash: _secretHash, ...summary }) => summary);
    },

    async revoke(id, now) {
      const existing = await this.findById(id);
      if (!existing) return false;
      if (existing.revokedAt === null) {
        await db.update(apiKeys).set({ revokedAt: now }).where(eq(apiKeys.id, id));
      }
      return true;
    },
  };
}

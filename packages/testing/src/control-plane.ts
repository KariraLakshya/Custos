import {
  createApiKeyStore,
  createControlPlaneGuard,
  type ControlPlaneGuard,
  type PrincipalKind,
  type Scope,
} from "@custos/control-plane-auth";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";

export interface TestControlPlane {
  /** A real guard over the real `api_keys` table, for a service's `controlPlaneAuth`. */
  readonly guard: ControlPlaneGuard;
  /** Creates a real key in the table and returns the full key. */
  key(
    kind: PrincipalKind,
    scopes: readonly Scope[],
    options?: { readonly expiresAt?: Date },
  ): Promise<string>;
}

/** Valid for a year from `clock.now()` unless `expiresAt` says otherwise. */
export function createTestControlPlane<TSchema extends Record<string, unknown>>(
  db: NodePgDatabase<TSchema>,
  clock: { now(): Date } = { now: () => new Date() },
): TestControlPlane {
  const store = createApiKeyStore(db);
  return {
    guard: createControlPlaneGuard({ keys: store, clock }),
    async key(kind, scopes, options = {}) {
      const now = clock.now();
      // Created a day "earlier" so a key with an explicit past expiry is still valid to insert.
      const createdAt = new Date(
        Math.min(now.getTime(), (options.expiresAt ?? now).getTime()) - 86_400_000,
      );
      const result = await store.create({
        kind,
        name: `test-${kind}`,
        scopes,
        expiresAt: options.expiresAt ?? new Date(now.getTime() + 365 * 86_400_000),
        now: createdAt,
      });
      if (!result.ok) throw new Error(`test key not created: ${result.error.code}`);
      return result.token;
    },
  };
}

export function bearer(token: string): { authorization: string } {
  return { authorization: `Bearer ${token}` };
}

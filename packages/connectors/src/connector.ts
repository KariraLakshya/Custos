import type { Result } from "@custos/contracts";

export type ConnectorCallError =
  | { readonly code: "UNKNOWN_ACTION"; readonly action: string }
  | { readonly code: "INVALID_INPUT"; readonly reason: string }
  | { readonly code: "AGENT_REVOKED"; readonly agentId: string }
  | { readonly code: "UPSTREAM_ERROR"; readonly status?: number; readonly reason: string };

// Per-tool adapters (Stripe, mock-slack, mock-database, ...) implement this.
export interface Connector {
  readonly tool: string;
  /**
   * Invokes one scoped action against the tool, using a credential the
   * caller has already decrypted — the connector never stores or logs it.
   *
   * `agentId` is the calling agent's did:web DID. The vault already refuses
   * revoked agents before it gets here, so an adapter enforcing revocation
   * itself is defence in depth rather than the only gate — but it is what
   * makes "adapters honour revocation" true at the tool boundary, and it is
   * the identity a real tool would use to scope or attribute the call.
   */
  call(params: {
    readonly action: string;
    readonly input: unknown;
    readonly credential: string;
    readonly agentId: string;
  }): Promise<Result<unknown, ConnectorCallError>>;
  /**
   * Withdraws this agent's access at the tool itself, so a compromised agent
   * is cut off even by a caller that skipped the vault. Idempotent: a
   * re-broadcast tombstone must not fail.
   */
  revoke(agentId: string): Promise<void>;
}

/**
 * Shared local revocation guard every connector composes. Adapters for real
 * tools should additionally withdraw access upstream (delete a per-agent
 * restricted key, for example) — this is the floor, not the ceiling.
 */
export function createRevocationGuard(): {
  readonly revoke: (agentId: string) => void;
  readonly isRevoked: (agentId: string) => boolean;
} {
  const revoked = new Set<string>();
  return {
    revoke: (agentId: string) => {
      revoked.add(agentId);
    },
    isRevoked: (agentId: string) => revoked.has(agentId),
  };
}

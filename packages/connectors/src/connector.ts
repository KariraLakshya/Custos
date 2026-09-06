import type { Result } from "@custos/contracts";

export type ConnectorCallError =
  | { readonly code: "UNKNOWN_ACTION"; readonly action: string }
  | { readonly code: "INVALID_INPUT"; readonly reason: string }
  | { readonly code: "UPSTREAM_ERROR"; readonly status?: number; readonly reason: string };

// Per-tool adapters (Stripe, mock-slack, mock-database, ...) implement this.
export interface Connector {
  readonly tool: string;
  /**
   * Invokes one scoped action against the tool, using a credential the
   * caller has already decrypted — the connector never stores or logs it.
   */
  call(params: {
    readonly action: string;
    readonly input: unknown;
    readonly credential: string;
  }): Promise<Result<unknown, ConnectorCallError>>;
  // Phase 3: real revocation broadcast so a compromised agent's access is
  // pulled at the tool itself, not just no-longer-tokenable from the vault.
  revoke(agentId: string): Promise<void>;
}

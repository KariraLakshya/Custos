// Per-tool adapters (GitHub, Stripe, ...) implement this from Phase 2 onward.
export interface Connector {
  readonly tool: string;
  revoke(agentId: string): Promise<void>;
}

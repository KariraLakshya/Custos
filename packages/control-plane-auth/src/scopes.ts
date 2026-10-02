/** Scopes an operator key may hold (ADR 0008 §3). */
export const OPERATOR_SCOPES = [
  "credentials:write",
  "policies:write",
  "agents:revoke",
  "agents:register",
] as const;

/** Scopes only a service key may hold: Custos components calling each other. */
export const SERVICE_ONLY_SCOPES = ["audit:write", "status:allocate"] as const;

export const ALL_SCOPES = [...OPERATOR_SCOPES, ...SERVICE_ONLY_SCOPES] as const;

export type Scope = (typeof ALL_SCOPES)[number];

export type PrincipalKind = "operator" | "service";

export function isScope(value: string): value is Scope {
  return (ALL_SCOPES as readonly string[]).includes(value);
}

/** Whether a key of `kind` may hold `scope`. Operator keys never get service-only scopes. */
export function scopeAllowedFor(kind: PrincipalKind, scope: Scope): boolean {
  return kind === "service" || !(SERVICE_ONLY_SCOPES as readonly string[]).includes(scope);
}

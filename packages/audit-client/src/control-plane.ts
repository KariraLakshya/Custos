import type { AuditEvent, AuditPrincipal } from "@custos/contracts";

/**
 * The audit event for one control-plane decision (ADR 0008 §7): who acted
 * (`principal`), what they did (`action`, e.g. `agents.revoke`), on what
 * (`agentDid` and/or `tool`, when known), and whether the scope check let
 * them. `principal` is taken structurally, so a control-plane `Principal`
 * (which also carries scopes) can be passed as-is; only kind, id and name are
 * recorded.
 */
export function controlPlaneEvent(params: {
  readonly principal: AuditPrincipal;
  readonly scope: string;
  readonly action: string;
  readonly decision: "allow" | "deny";
  readonly agentDid?: string;
  readonly tool?: string;
  readonly reason?: string;
}): AuditEvent {
  const { principal } = params;
  return {
    principal: { kind: principal.kind, id: principal.id, name: principal.name },
    action: params.action,
    dataCategories: [],
    policy: { rule: `control-plane-scope:${params.scope}`, decision: params.decision },
    ...(params.agentDid === undefined ? {} : { agentDid: params.agentDid }),
    ...(params.tool === undefined ? {} : { tool: params.tool }),
    ...(params.reason === undefined ? {} : { reason: params.reason }),
  };
}

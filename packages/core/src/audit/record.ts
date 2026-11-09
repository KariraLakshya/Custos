/**
 * Who made a control-plane call (ADR 0008 §7): an operator or a Custos
 * service, identified by its API key's id. Never the key itself.
 */
export interface AuditPrincipal {
  readonly kind: "operator" | "service";
  readonly id: string;
  readonly name: string;
}

/**
 * An append-only record of one action (CLAUDE.md section 10: "every audit
 * record carries the agent identity, the authority chain it acted under, the
 * data categories touched, the policy applied, the decision, and a
 * signature"). It is stored as one entry of the audit ledger, whose seals
 * carry the signature (ADR 0017, `ledger.ts`).
 *
 * Two kinds, one shape. An **agent action** has `agentDid` and `tool`, and
 * `authorityChain` is `[agentDid]`, or, for an agent acting under a
 * delegation (ADR 0020 §6), every agent from the first delegator to
 * `agentDid`, with `delegationRef` naming the chain. A **control-plane action** (ADR 0008 §7) has a `principal`, the
 * operator or service that acted, and `authorityChain` is `[]` because no
 * agent acted; `agentDid` and `tool` name what it acted on, when anything.
 * Every record names an actor: an `agentDid`, a `principal`, or both.
 */
export interface AuditRecord {
  readonly agentDid?: string;
  readonly principal?: AuditPrincipal;
  readonly authorityChain: readonly string[];
  readonly tool?: string;
  readonly action: string;
  readonly dataCategories: readonly string[];
  readonly policy: { readonly rule: string; readonly decision: "allow" | "deny" };
  readonly reason?: string;
  readonly recordedAt: string;
  /**
   * The authenticated service or operator that sent this record to the audit
   * service (ADR 0017), as opposed to `principal`, the one that acted. Absent
   * on records stored before it was recorded.
   */
  readonly reportedBy?: AuditPrincipal;
  /**
   * For a delegated action (ADR 0020 §6): the hash of the hand-off naming
   * `agentDid`, the same on the token's issuance entry and on every call
   * made with it.
   */
  readonly delegationRef?: string;
  /** On the issuance entry only: the chain's evidence, re-checkable offline. */
  readonly delegation?: AuditDelegationEvidence;
}

/**
 * What a delegated token was issued under (ADR 0020 §6). `root` is the
 * operator whose grant to the first delegator the chain starts from; the
 * hand-offs and credentials are as presented, so the chain can be verified
 * again with `verifyDelegationChain` at `checkedAt`, the vault's own time of
 * the check.
 */
export interface AuditDelegationEvidence {
  readonly root: AuditPrincipal & { readonly via?: "custos-admin" | "sso" };
  readonly handOffs: readonly string[];
  readonly credentials: readonly unknown[];
  readonly checkedAt: string;
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isAuditPrincipal(value: unknown): value is AuditPrincipal {
  if (typeof value !== "object" || value === null) return false;
  const principal = value as Record<string, unknown>;
  return (
    (principal.kind === "operator" || principal.kind === "service") &&
    isNonEmptyString(principal.id) &&
    isNonEmptyString(principal.name)
  );
}

function isDelegationEvidence(value: unknown): value is AuditDelegationEvidence {
  if (typeof value !== "object" || value === null) return false;
  const evidence = value as Record<string, unknown>;
  const root = evidence.root as Record<string, unknown> | null | undefined;
  return (
    isAuditPrincipal(root) &&
    (root.via === undefined || root.via === "custos-admin" || root.via === "sso") &&
    isStringArray(evidence.handOffs) &&
    Array.isArray(evidence.credentials) &&
    typeof evidence.checkedAt === "string"
  );
}

/** Whether `value` has the shape of an `AuditRecord`; used to read a ledger entry's payload. */
export function isAuditRecord(value: unknown): value is AuditRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  if (record.agentDid !== undefined && !isNonEmptyString(record.agentDid)) return false;
  if (record.principal !== undefined && !isAuditPrincipal(record.principal)) return false;
  // Every record names who acted.
  if (record.agentDid === undefined && record.principal === undefined) return false;
  if (!isStringArray(record.authorityChain)) return false;
  if (record.tool !== undefined && !isNonEmptyString(record.tool)) return false;
  if (typeof record.action !== "string" || record.action.length === 0) return false;
  if (!isStringArray(record.dataCategories)) return false;
  if (typeof record.recordedAt !== "string") return false;
  if (record.reason !== undefined && typeof record.reason !== "string") return false;
  if (record.reportedBy !== undefined && !isAuditPrincipal(record.reportedBy)) return false;
  if (record.delegationRef !== undefined && !isNonEmptyString(record.delegationRef)) return false;
  if (record.delegation !== undefined) {
    if (record.delegationRef === undefined || !isDelegationEvidence(record.delegation))
      return false;
  }
  const policy = record.policy;
  if (typeof policy !== "object" || policy === null) return false;
  const policyFields = policy as Record<string, unknown>;
  if (typeof policyFields.rule !== "string") return false;
  if (policyFields.decision !== "allow" && policyFields.decision !== "deny") return false;
  return true;
}

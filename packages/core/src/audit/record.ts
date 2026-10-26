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
 * `authorityChain` is `[agentDid]`: flat today because no delegation exists
 * yet (Phase 6); a delegation chain extends the array without changing the
 * shape. A **control-plane action** (ADR 0008 §7) has a `principal`, the
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
  const policy = record.policy;
  if (typeof policy !== "object" || policy === null) return false;
  const policyFields = policy as Record<string, unknown>;
  if (typeof policyFields.rule !== "string") return false;
  if (policyFields.decision !== "allow" && policyFields.decision !== "deny") return false;
  return true;
}

import { z } from "zod";

/** The operator or service behind a control-plane action (ADR 0008 §7). */
export const auditPrincipalSchema = z.object({
  kind: z.enum(["operator", "service"]),
  id: z.string().min(1).max(64),
  name: z.string().min(1).max(100),
});

/**
 * Bounds for delegation evidence (ADR 0020 §6). They admit the largest chain
 * a vault can be configured to accept (`DELEGATION_MAX_BYTES` ≤ 256 KiB over
 * hand-offs and credentials, at most 16 of each), so a genuine chain is never
 * refused here, and the whole event stays well under the audit service's
 * 1 MiB body limit.
 */
export const MAX_DELEGATION_EVIDENCE_BYTES = 262_144 + 4_096;
const MAX_CHAIN_ENTRIES = 16;

const delegationEvidenceSchema = z.object({
  root: auditPrincipalSchema.extend({ via: z.enum(["custos-admin", "sso"]).optional() }),
  handOffs: z.array(z.string().min(1).max(262_144)).min(1).max(MAX_CHAIN_ENTRIES),
  credentials: z.array(z.unknown()).min(1).max(MAX_CHAIN_ENTRIES),
  checkedAt: z.string().datetime(),
});

/**
 * What a service reports to the audit service's `POST /records`. An agent
 * action names the agent (and usually a tool); a control-plane action names
 * the principal that made it. Every event names at least one actor, the same
 * rule `@custos/core`'s `AuditRecord` enforces when a record is verified.
 */
export const auditEventSchema = z
  .object({
    agentDid: z.string().min(1).max(512).optional(),
    principal: auditPrincipalSchema.optional(),
    tool: z.string().min(1).max(128).optional(),
    action: z.string().min(1).max(128),
    dataCategories: z.array(z.string().max(128)).max(64),
    policy: z.object({ rule: z.string().min(1).max(256), decision: z.enum(["allow", "deny"]) }),
    reason: z.string().min(1).max(1024).optional(),
    /**
     * A delegated agent action only (ADR 0020 §6): every agent from the first
     * delegator to `agentDid`, which is last. Absent, the audit service
     * records `[agentDid]` as before.
     */
    authorityChain: z.array(z.string().min(1).max(512)).min(2).max(MAX_CHAIN_ENTRIES).optional(),
    /** With `authorityChain`, and only with it: the hand-off hash naming the chain. */
    delegationRef: z.string().min(1).max(64).optional(),
    /** On the token's issuance entry only: the chain's evidence. */
    delegation: delegationEvidenceSchema.optional(),
  })
  .refine((event) => event.agentDid !== undefined || event.principal !== undefined, {
    message: "an audit event must name an agent or a principal",
  })
  .refine(
    (event) =>
      event.authorityChain === undefined ||
      (event.principal === undefined && event.authorityChain.at(-1) === event.agentDid),
    { message: "a delegation chain belongs to an agent action and ends at its agent" },
  )
  .refine((event) => (event.authorityChain === undefined) === (event.delegationRef === undefined), {
    message: "a delegation chain and its reference come together",
  })
  .refine((event) => event.delegation === undefined || event.delegationRef !== undefined, {
    message: "delegation evidence needs its chain",
  })
  .refine(
    (event) =>
      event.delegation === undefined ||
      JSON.stringify(event.delegation).length <= MAX_DELEGATION_EVIDENCE_BYTES,
    { message: "delegation evidence is too large" },
  );

export type AuditPrincipal = z.infer<typeof auditPrincipalSchema>;
type ParsedAuditEvent = z.infer<typeof auditEventSchema>;
type ParsedDelegationEvidence = z.infer<typeof delegationEvidenceSchema>;
/**
 * Read-only where callers hold read-only data (a connector's
 * `dataCategories`, a verified chain).
 */
export type AuditEvent = Omit<
  ParsedAuditEvent,
  "dataCategories" | "authorityChain" | "delegation"
> & {
  readonly dataCategories: readonly string[];
  readonly authorityChain?: readonly string[];
  readonly delegation?: Omit<ParsedDelegationEvidence, "handOffs" | "credentials"> & {
    readonly handOffs: readonly string[];
    readonly credentials: readonly unknown[];
  };
};

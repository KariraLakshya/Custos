import { agentNameSchema } from "./agent-name.js";
import {
  REFUSALS,
  UNKNOWN_REFUSAL,
  refusalFor,
  type RefusalCode,
  type RefusalEntry,
} from "./refusals.js";

/**
 * One audit event as a sentence a person reads (ADR 0022 §5 and §7): "alice
 * cut off billing-bot: key leaked", "billing-bot used mock-database (query):
 * allowed". Shared by the dashboard's view models and `custos audit-log`, so
 * the two never describe the same entry differently.
 *
 * Everything here came over the network, even from a verified log: a sealed
 * entry proves what a service wrote, not that it is safe to print. Names
 * pass `agentNameSchema`; every other string is printed only if it is plain
 * printable ASCII on one line, else replaced by words. The output is plain
 * text: a page still escapes it (the dashboard's `escapeHtml`).
 */

/** The fields of a verified audit record these words read; `@custos/core`'s `AuditRecord` fits. */
export interface EventRecord {
  readonly agentDid?: string;
  readonly principal?: { readonly kind: string; readonly name: string };
  readonly authorityChain: readonly string[];
  readonly tool?: string;
  readonly action: string;
  readonly policy: { readonly rule: string; readonly decision: "allow" | "deny" };
  readonly reason?: string;
  readonly delegationRef?: string;
  readonly delegation?: {
    readonly root: { readonly kind: string; readonly name: string };
  };
}

const PRINTABLE = /^[\x21-\x7E](?:[\x20-\x7E]*[\x21-\x7E])?$/;
const CODE = /^[A-Z0-9_]{1,64}$/;

/** `value` if it is printable ASCII on one line, at most `max` long; else undefined. */
export function plainText(value: unknown, max = 128): string | undefined {
  return typeof value === "string" && value.length <= max && PRINTABLE.test(value)
    ? value
    : undefined;
}

/**
 * How an agent is shown: its name if it passes the naming rule, else
 * "unnamed · …" and the last four characters of its DID (dashboard plan,
 * "Names first"). A DID that is not plain text is not shown at all.
 */
export function agentLabel(did: unknown, name?: unknown): string {
  const named = agentNameSchema.safeParse(name);
  if (named.success) return named.data;
  const shown = plainText(did, 512);
  return shown === undefined ? "unnamed · (id not shown)" : `unnamed · …${shown.slice(-4)}`;
}

/** An operator or service, by its name when that is plain text. */
export function principalLabel(principal: EventRecord["principal"]): string {
  if (principal === undefined) return "someone";
  return (
    plainText(principal.name, 128) ?? (principal.kind === "service" ? "a service" : "an operator")
  );
}

/** A refusal recorded in the audit log, as the catalogue explains it. */
export interface RecordedRefusal {
  /** The catalogue code; `UNKNOWN` for a rule this version does not recognise. */
  readonly code: RefusalCode;
  readonly entry: RefusalEntry;
}

/**
 * The refusal a denied entry records. Entries carry the rule that decided
 * and a free-text reason, not a code, so the code is read from the rule the
 * services write (vault `deniedAtIssue` and `/call`, the control-plane scope
 * guard). An unrecognised rule is `UNKNOWN`: normal, never red by accident.
 * Undefined for an allowed entry.
 */
export function refusalOfRecord(record: EventRecord): RecordedRefusal | undefined {
  if (record.policy.decision !== "deny") return undefined;
  const { rule } = record.policy;
  const reason = record.reason;
  const code = ((): RefusalCode | undefined => {
    if (rule === "agent-tool-allowlist") return "POLICY_DENIED";
    if (rule === "revocation") return "AGENT_REVOKED";
    if (rule === "revocation-state-unknown") return "REVOCATION_STATE_UNKNOWN_AGENT";
    if (rule === "revocation-state-stale") return "REVOCATION_STATE_STALE";
    if (rule === "token-scope") return "ACTION_MISMATCH";
    if (rule === "unknown-tool") return "UNKNOWN_TOOL";
    if (rule.startsWith("delegation:")) return "DELEGATION_DENIED";
    if (rule.startsWith("control-plane-scope:")) return "UNAUTHORIZED";
    // The connector's own error code is the reason (vault `invoke.ts`).
    if (rule === "connector" && typeof reason === "string" && CODE.test(reason)) {
      return Object.hasOwn(REFUSALS, reason) ? (reason as RefusalCode) : undefined;
    }
    return undefined;
  })();
  if (code === undefined) return { code: "UNKNOWN", entry: UNKNOWN_REFUSAL };
  if (code === "DELEGATION_DENIED") {
    // "delegation chain refused: NOT_COVERED" carries the finer reason.
    const finer = typeof reason === "string" ? /: ([A-Z_]{1,64})$/.exec(reason)?.[1] : undefined;
    return { code, entry: refusalFor(code, finer) };
  }
  return { code, entry: refusalFor(code) };
}

export interface EventWordsOptions {
  /** How to show an agent, by DID; default `agentLabel(did)` (no names known). */
  readonly agent?: (did: string) => string;
  /**
   * For a delegated entry: who the chain starts from, when the caller has
   * linked it (a call entry carries no root; its issuance entry does).
   */
  readonly chainRoot?: string;
}

function decided(refusal: RecordedRefusal | undefined): string {
  return refusal === undefined ? "allowed" : `refused. ${refusal.entry.meaning}`;
}

/**
 * The chain a delegated entry acted under, as "alice → billing-bot →
 * helper-bot" (dashboard plan, "Who can do what"). Undefined for an entry
 * that was not delegated.
 */
export function chainWords(
  record: EventRecord,
  options: EventWordsOptions = {},
): string | undefined {
  if (record.delegationRef === undefined && record.authorityChain.length < 2) return undefined;
  const label = options.agent ?? ((did: string) => agentLabel(did));
  const root =
    record.delegation === undefined ? options.chainRoot : principalLabel(record.delegation.root);
  return [root ?? "(not linked)", ...record.authorityChain.map(label)].join(" → ");
}

/** One verified audit entry as one sentence. Never throws. */
export function eventSentence(record: EventRecord, options: EventWordsOptions = {}): string {
  const label = options.agent ?? ((did: string) => agentLabel(did));
  const agent = record.agentDid === undefined ? undefined : label(record.agentDid);
  const tool = record.tool === undefined ? undefined : (plainText(record.tool, 64) ?? "a tool");
  const action = plainText(record.action, 64) ?? "an action";
  const refusal = refusalOfRecord(record);

  if (record.principal !== undefined) {
    const who = principalLabel(record.principal);
    const whom = agent ?? "an agent";
    const allowed = refusal === undefined;
    switch (record.action) {
      case "agents.revoke": {
        if (!allowed) return `${who} tried to cut off ${whom}: ${decided(refusal)}`;
        const why = record.reason === undefined ? undefined : plainText(record.reason, 200);
        return why === undefined ? `${who} cut off ${whom}` : `${who} cut off ${whom}: ${why}`;
      }
      case "agents.register":
        return allowed
          ? `${who} registered ${whom}`
          : `${who} tried to register an agent: ${decided(refusal)}`;
      case "policies.grant":
        return allowed
          ? `${who} gave ${whom} ${tool ?? "a tool"}`
          : `${who} tried to give ${whom} ${tool ?? "a tool"}: ${decided(refusal)}`;
      case "credentials.store":
        return allowed
          ? `${who} stored the credential for ${tool ?? "a tool"}`
          : `${who} tried to store the credential for ${tool ?? "a tool"}: ${decided(refusal)}`;
      case "status.allocate":
        return allowed
          ? `${who} reserved ${whom}'s place on the revocation list`
          : `${who} tried to reserve a place on the revocation list: ${decided(refusal)}`;
      case "operator.login":
        return allowed ? `${who} signed in` : `${who} tried to sign in: ${decided(refusal)}`;
      default:
        return `${who} did ${action}${agent === undefined ? "" : ` on ${agent}`}: ${allowed ? "allowed" : decided(refusal)}`;
    }
  }

  const subject = agent ?? "an agent";
  const what = tool === undefined ? action : `${tool} (${action})`;
  const chain = chainWords(record, options);
  const forWhom = chain === undefined ? "" : ` for ${chain}`;
  if (record.delegation !== undefined) {
    return `${subject} was given a pass for ${what}${forWhom}: ${decided(refusal)}`;
  }
  return refusal === undefined
    ? `${subject} used ${what}${forWhom}: allowed`
    : `${subject} asked to use ${what}${forWhom}: ${decided(refusal)}`;
}

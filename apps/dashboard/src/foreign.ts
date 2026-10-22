// Runs in the browser as well as in tests: `tsc` emits it as a plain ES module
// (dist/foreign.js), which index.html imports. No imports, no Node APIs.

/** One decision this organisation made about another organisation's agent. */
export interface ForeignView {
  /** The trust anchor's label for the other organisation, from `policy.rule`. */
  readonly organisation: string;
  readonly agentDid: string;
  readonly decision: "allow" | "deny";
  /** The denial code (`AGENT_REVOKED`, `STATUS_STALE`, …); undefined for an allow. */
  readonly code: string | undefined;
  readonly tool: string | undefined;
  readonly recordedAt: string;
}

const RULE_PREFIX = "foreign:";
const CODE = /(?:^|\s)code=([A-Z][A-Z_]*)(?:\s|$)/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The denial code a gate writes into `reason` (`issuer=… code=AGENT_REVOKED`). */
export function codeFromReason(reason: unknown): string | undefined {
  if (typeof reason !== "string") return undefined;
  return CODE.exec(reason)?.[1];
}

/**
 * The cross-organisation view of one decoded audit record, or `undefined` for
 * anything that is not a `foreign:` decision or is malformed. Never throws:
 * the record came over the network, and a bad one is skipped, not fatal.
 */
export function foreignViewOf(claims: unknown): ForeignView | undefined {
  if (!isRecord(claims)) return undefined;
  const { policy, agentDid, recordedAt, tool } = claims;
  if (!isRecord(policy) || typeof policy.rule !== "string") return undefined;
  if (!policy.rule.startsWith(RULE_PREFIX)) return undefined;
  const organisation = policy.rule.slice(RULE_PREFIX.length);
  if (organisation === "") return undefined;
  if (policy.decision !== "allow" && policy.decision !== "deny") return undefined;
  if (typeof agentDid !== "string" || agentDid === "") return undefined;
  if (typeof recordedAt !== "string" || Number.isNaN(Date.parse(recordedAt))) return undefined;
  return {
    organisation,
    agentDid,
    decision: policy.decision,
    code: policy.decision === "deny" ? codeFromReason(claims.reason) : undefined,
    tool: typeof tool === "string" ? tool : undefined,
    recordedAt,
  };
}

/** Only what happened since the page opened, so a rehearsal's rows don't open the show. */
export function recordedSince(view: ForeignView, sinceMs: number): boolean {
  return Date.parse(view.recordedAt) >= sinceMs;
}

/** The toast for an agent cut off by its own organisation, or undefined for anything else. */
export function cutOffMessage(view: ForeignView, shortAgent: string): string | undefined {
  if (view.decision !== "deny" || view.code !== "AGENT_REVOKED") return undefined;
  return `🔌 ${shortAgent} from ${view.organisation} refused: revoked by its own organisation`;
}

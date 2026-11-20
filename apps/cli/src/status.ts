import { agentNameSchema } from "@custos/contracts";
import type { AuditRecord } from "@custos/core";
import {
  CustosError,
  type Custos,
  type Grant,
  type Principal,
  type RegisteredAgent,
  type Revocation,
} from "@custos/sdk";
import type { AuditLogResult } from "./audit-log.js";
import {
  acceptKeyHelp,
  auditFailureWords,
  explainAuditFailure,
  untrustedKeyOf,
  type AuditFailureWords,
} from "./audit-words.js";
import { explainRefusal } from "./refusal-words.js";

/**
 * `custos status <agent>` (ADR 0022 §7): one agent's name, grants, revocation
 * and recent actions, read from the four services with the operator key.
 *
 * Each source is reported on its own. One that cannot be read is shown as
 * "could not check", never as an empty answer: a revocation read that failed
 * is not "not cut off", and a grants read that failed is not "no tools".
 */

/** Why one read gave no answer. */
export type ReadFailure =
  | {
      readonly kind: "refused";
      readonly code: string;
      readonly reason?: string;
      readonly status?: number;
    }
  | { readonly kind: "unreachable" }
  | { readonly kind: "bad-response" };

type Read<T> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly failure: ReadFailure };

export interface AgentStatus {
  /** The agent's id and DID: identity's when it answered, else worked out from the argument. */
  readonly agent: { readonly id: string; readonly did: string };
  readonly identity: Read<RegisteredAgent>;
  readonly grants: Read<readonly Grant[]>;
  readonly revocation: Read<Revocation | null>;
  readonly audit: AuditLogResult;
}

/** The services read, the scope each read needs (ADR 0022 §3), and what it tells. */
export const SOURCES = {
  identity: { service: "identity service", scope: "agents:read", what: "who this agent is" },
  grants: { service: "vault", scope: "policies:read", what: "what it may use" },
  revocation: {
    service: "revocation service",
    scope: "revocations:read",
    what: "whether it is cut off",
  },
  audit: { service: "audit service", scope: "audit:read", what: "what it did recently" },
} as const;
type Source = keyof typeof SOURCES;

/** How many of the newest actions are shown. */
export const RECENT_ACTIONS = 5;

const AGENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function read<T>(run: () => Promise<T>): Promise<Read<T>> {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    if (!(error instanceof CustosError)) return { ok: false, failure: { kind: "bad-response" } };
    if (error.code === "SERVICE_UNREACHABLE") {
      return { ok: false, failure: { kind: "unreachable" } };
    }
    return {
      ok: false,
      failure: {
        kind: "refused",
        code: error.code,
        ...(error.reason === undefined ? {} : { reason: error.reason }),
        ...(error.status === undefined ? {} : { status: error.status }),
      },
    };
  }
}

/** Identity's answer must be the agent asked for, with a DID of the Custos shape. */
function isAgentAskedFor(
  agent: RegisteredAgent,
  ref: { readonly id: string; readonly did: string },
  byDid: boolean,
): boolean {
  if (!AGENT_ID.test(agent.id)) return false;
  if (byDid ? agent.did !== ref.did : agent.id.toLowerCase() !== ref.id.toLowerCase()) {
    return false;
  }
  return agent.did.endsWith(`:agents:${agent.id}`) && /^did:web:[A-Za-z0-9.%:_-]+$/.test(agent.did);
}

/**
 * Reads everything about one agent. Identity first: it says whether the agent
 * exists and gives the DID the other three reads use. If identity cannot be
 * read, they use the DID worked out from the argument, and the report says so.
 * Returns "unknown-agent" when identity answered and has no such agent.
 */
export async function gatherStatus(params: {
  readonly custos: Custos;
  readonly ref: { readonly id: string; readonly did: string };
  /** True when the operator named the agent by DID rather than id. */
  readonly byDid: boolean;
  readonly pullAudit: (agentDid: string) => Promise<AuditLogResult>;
}): Promise<AgentStatus | "unknown-agent"> {
  const { custos, ref, byDid } = params;
  const found = await read(() => custos.findAgent(byDid ? { did: ref.did } : { id: ref.id }));
  if (found.ok && found.value === null) return "unknown-agent";
  let identity: Read<RegisteredAgent>;
  if (!found.ok) identity = found;
  else if (found.value !== null && isAgentAskedFor(found.value, ref, byDid)) {
    identity = { ok: true, value: found.value };
  } else identity = { ok: false, failure: { kind: "bad-response" } };

  const agent = identity.ok ? { id: identity.value.id, did: identity.value.did } : ref;
  const [grants, revocation, audit] = await Promise.all([
    read(() => custos.listGrants(agent)),
    read(() => custos.findRevocation(agent)),
    params.pullAudit(agent.did),
  ]);
  return { agent, identity, grants, revocation, audit };
}

// Strings off the wire are printed only if they are plain, printable ASCII on
// one line, so a service cannot write control characters or fake lines to
// the terminal. Anything else is left to --json, where JSON escapes it.
const PRINTABLE = /^[\x21-\x7E](?:[\x20-\x7E]*[\x21-\x7E])?$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;

function safeText(value: unknown, max = 128): string | undefined {
  return typeof value === "string" && value.length <= max && PRINTABLE.test(value)
    ? value
    : undefined;
}

function safeTime(value: unknown): string {
  return typeof value === "string" && TIMESTAMP.test(value) ? value : "(time not shown)";
}

function principalWords(principal: Principal | null | undefined): string | undefined {
  if (principal === null || principal === undefined) return undefined;
  return safeText(principal.name) ?? (principal.kind === "service" ? "a service" : "an operator");
}

/** The agent's name if it passes the naming rule, else "unnamed" and a short DID. */
function agentLabel(agent: { readonly did: string; readonly id: string }, name: unknown): string {
  const shown = agentNameSchema.safeParse(name);
  if (shown.success) return shown.data;
  const short = `${agent.did.slice(0, agent.did.length - agent.id.length)}${agent.id.slice(0, 8)}…`;
  return name === null || name === undefined
    ? `unnamed (${short})`
    : `unnamed (${short}; its stored name cannot be shown safely)`;
}

type AuditOutcome =
  | { readonly state: "verified"; readonly recent: readonly AuditEntry[] }
  | { readonly state: "failed"; readonly failure: ReadFailure }
  | { readonly state: "not-verified"; readonly words: AuditFailureWords };
type AuditEntry = { readonly seq: number; readonly record: AuditRecord };

function auditOutcome(audit: AuditLogResult): AuditOutcome {
  if (audit.verified) {
    const recent = [...audit.records].sort((a, b) => b.seq - a.seq).slice(0, RECENT_ACTIONS);
    return { state: "verified", recent };
  }
  const { error } = audit;
  if (error.code === "UNREACHABLE") return { state: "failed", failure: { kind: "unreachable" } };
  // The guard answers every missing key or scope with 401 (ADR 0008 §3).
  if (error.code === "BAD_RESPONSE" && error.status === 401) {
    return {
      state: "failed",
      failure: { kind: "refused", code: "UNAUTHORIZED", status: 401 },
    };
  }
  return { state: "not-verified", words: auditFailureWords(error) };
}

function cause(source: Source, failure: ReadFailure): string {
  const { service, scope } = SOURCES[source];
  switch (failure.kind) {
    case "unreachable":
      return `the ${service} did not answer`;
    case "bad-response":
      return `the ${service}'s answer was not in the shape this command expects`;
    case "refused":
      return failure.code === "UNAUTHORIZED"
        ? `the ${service} refused the read; the key needs ${scope}`
        : `the ${service} refused the read`;
  }
}

/** The stderr lines for one source that could not be read. */
function explainFailure(source: Source, failure: ReadFailure): string {
  const { service, scope, what } = SOURCES[source];
  switch (failure.kind) {
    case "unreachable":
      return `Could not check ${what}: the ${service} did not answer.\n${explainRefusal("SERVICE_UNREACHABLE", undefined)}`;
    case "bad-response":
      return [
        `Could not check ${what}: the ${service}'s answer was not in the shape this command expects.`,
        `Next: check that the ${service} and the custos command are the same version.`,
        "",
      ].join("\n");
    case "refused":
      return [
        failure.code === "UNAUTHORIZED"
          ? `Could not check ${what}: the ${service} refused the read. The key needs ${scope}.`
          : `Could not check ${what}: the ${service} refused the read.`,
        explainRefusal(failure.code, failure.reason),
      ].join("\n");
  }
}

function actionWords(entry: AuditEntry): string {
  const { record } = entry;
  const who = record.principal === undefined ? "the agent" : principalWords(record.principal);
  const action = safeText(record.action, 64) ?? "(an action not shown)";
  const tool = record.tool === undefined ? undefined : (safeText(record.tool, 64) ?? "(a tool)");
  const decision = record.policy.decision === "allow" ? "allowed" : "refused";
  return `  #${entry.seq} ${safeTime(record.recordedAt)}  ${who} ${tool === undefined ? action : `${action} on ${tool}`}: ${decision}`;
}

/** Who cut the agent off, from the verified audit log's own entry for it. */
function revokedBy(audit: AuditLogResult): string | undefined {
  if (!audit.verified) return undefined;
  const entry = [...audit.records]
    .sort((a, b) => b.seq - a.seq)
    .find((e) => e.record.action === "agents.revoke" && e.record.policy.decision === "allow");
  return principalWords(entry?.record.principal);
}

export interface RenderedStatus {
  readonly stdout: string;
  readonly stderr: string;
  /** 0 only when every source was read and the audit log verified. */
  readonly exitCode: 0 | 1;
}

export function renderStatus(
  status: AgentStatus,
  options: { readonly json?: boolean } = {},
): RenderedStatus {
  const { agent, identity, grants, revocation } = status;
  const audit = auditOutcome(status.audit);
  const out: string[] = [];
  const err: string[] = [];
  let complete = true;
  // Without identity, an empty answer may only mean the DID was worked out wrong.
  const unconfirmed = identity.ok ? "" : " (not confirmed: identity could not be read)";
  const failed = (source: Source, failure: ReadFailure): void => {
    complete = false;
    err.push(explainFailure(source, failure));
  };

  // Who it is.
  if (identity.ok) {
    const { name, registeredAt, registeredBy } = identity.value;
    const by = principalWords(registeredBy);
    out.push(
      `${agentLabel(agent, name)} (id ${agent.id})`,
      `  Registered ${safeTime(registeredAt)}${by === undefined ? "; who registered it was not recorded" : ` by ${by}`}.`,
    );
  } else {
    failed("identity", identity.failure);
    out.push(
      `Agent ${agent.id}`,
      `  Could not check who this agent is (${cause("identity", identity.failure)}).`,
      `  The lines below are for ${agent.did}, worked out from what you typed: an empty answer there is not confirmed.`,
    );
  }

  // What it may use.
  if (!grants.ok) {
    failed("grants", grants.failure);
    out.push(
      `  May use: could not check (${cause("grants", grants.failure)}). It may hold grants not shown here.`,
    );
  } else if (grants.value.length === 0) {
    out.push(`  May use: no tools${unconfirmed}.`);
  } else {
    out.push("  May use:");
    for (const grant of grants.value) {
      const by = principalWords(grant.grantedBy);
      out.push(
        `    ${safeText(grant.tool, 64) ?? "(a tool whose name cannot be shown safely; see --json)"}, granted ${safeTime(grant.createdAt)}${by === undefined ? "" : ` by ${by}`}`,
      );
    }
  }

  // Whether it is cut off.
  if (!revocation.ok) {
    failed("revocation", revocation.failure);
    out.push(
      `  Cut off: could not check (${cause("revocation", revocation.failure)}). Do not assume either way.`,
    );
  } else if (revocation.value === null) {
    out.push(`  Cut off: no${unconfirmed}.`);
  } else {
    const by = revokedBy(status.audit);
    const reason = revocation.value.reason;
    out.push(
      `  Cut off: yes, at ${safeTime(revocation.value.revokedAt)}${by === undefined ? "" : ` by ${by}`}.`,
    );
    if (reason !== undefined) {
      const shownReason = safeText(reason, 200);
      out.push(
        shownReason === undefined
          ? "  Reason: given, but it cannot be shown safely; see --json."
          : `  Reason: ${shownReason}`,
      );
    }
  }

  // What it did recently.
  if (audit.state === "verified") {
    if (audit.recent.length === 0) {
      out.push(`  Recent actions: none recorded${unconfirmed}.`);
    } else {
      out.push("  Recent actions, newest first (the audit log verified):");
      out.push(...audit.recent.map(actionWords));
    }
  } else if (audit.state === "failed") {
    failed("audit", audit.failure);
    out.push(`  Recent actions: could not check (${cause("audit", audit.failure)}).`);
  } else if (!status.audit.verified) {
    complete = false;
    const { error } = status.audit;
    err.push(explainAuditFailure(error));
    const key = untrustedKeyOf(error);
    if (key !== undefined) err.push(acceptKeyHelp(key));
    out.push(
      audit.words.kind === "tampered"
        ? "  Recent actions: ALARM. The audit log does not verify: it has been changed. Nothing from it is shown."
        : audit.words.kind === "needs-a-person"
          ? "  Recent actions: not checked. The audit log is sealed with a key this machine has not trusted yet."
          : `  Recent actions: could not check. ${audit.words.meaning}`,
    );
  }

  const revoked = revocation.ok && revocation.value !== null;
  const noGrants = grants.ok && grants.value.length === 0;
  out.push(
    !complete
      ? `Next: fix what is named above, then run again: custos status ${agent.id}`
      : !revoked && noGrants
        ? `Next: custos grant <tool> --to ${agent.id}`
        : `Next: custos audit-log ${agent.id}   (every recorded action, verified)`,
  );

  const stdout = options.json
    ? `${jsonForTerminal(statusJson(status, audit))}\n`
    : `${out.join("\n")}\n`;
  return { stdout, stderr: err.join(""), exitCode: complete ? 0 : 1 };
}

/**
 * JSON.stringify escapes only U+0000 to U+001F. DEL, the C1 controls (U+009B
 * starts a terminal command on some terminals), and the line, paragraph and
 * bidi controls are escaped too, so `--json` on a terminal is as safe as the
 * words. They can only occur inside strings, so the output stays valid JSON.
 */
export function jsonForTerminal(value: unknown): string {
  return JSON.stringify(value, null, 2).replace(
    /[\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function failureJson(source: Source, failure: ReadFailure) {
  return { ok: false, ...failure, service: SOURCES[source].service, scope: SOURCES[source].scope };
}

/** `--json`: the same facts, strings as the services sent them (JSON escapes them). */
function statusJson(status: AgentStatus, audit: AuditOutcome): unknown {
  const { agent, identity, grants, revocation } = status;
  return {
    agent,
    identity: identity.ok
      ? { ok: true, ...identity.value }
      : failureJson("identity", identity.failure),
    grants: grants.ok ? { ok: true, grants: grants.value } : failureJson("grants", grants.failure),
    revocation: !revocation.ok
      ? failureJson("revocation", revocation.failure)
      : revocation.value === null
        ? { ok: true, revoked: false }
        : { ok: true, revoked: true, ...revocation.value },
    audit: status.audit.verified
      ? {
          ok: true,
          verified: true,
          log: status.audit.log,
          headSeq: status.audit.headSeq,
          sealedThrough: status.audit.sealedThrough,
          outsideSealsChecked: status.audit.outsideSealsChecked,
          recent: audit.state === "verified" ? audit.recent : [],
        }
      : audit.state === "failed"
        ? failureJson("audit", audit.failure)
        : {
            ok: false,
            verified: false,
            kind: audit.state === "not-verified" ? audit.words.kind : "cannot-check",
            error: status.audit.error,
          },
  };
}

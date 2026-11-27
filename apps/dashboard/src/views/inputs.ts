import type {
  CheckedDelegation,
  DelegationAuditError,
  PullAuditLedgerError,
  PulledAuditLedger,
} from "@custos/audit-client/ledger";
import { agentLabel, plainText } from "@custos/contracts";
import { escapeHtml, type Escaped } from "./escape.js";

/**
 * What the view models read (ADR 0022 §5): plain data the dashboard's back
 * end gathers. Each source is read on its own and may fail on its own; a
 * source that could not be read is never shown as empty or fine.
 */

export type ServiceName = "identity" | "vault" | "revocation" | "audit";
export const SERVICES: readonly ServiceName[] = ["identity", "vault", "revocation", "audit"];

/** One read, in one of the states every screen handles (dashboard plan). */
export type Source<T> =
  | { readonly state: "loading" }
  | { readonly state: "ok"; readonly data: T; readonly readAt: string }
  /** The service did not answer, or answered with something unreadable. */
  | {
      readonly state: "failed";
      readonly service: ServiceName;
      /** The last answer that was read, shown greyed "as of" its time. */
      readonly lastGood?: { readonly data: T; readonly readAt: string };
    }
  /** The signed-in person's group lacks the read scope. */
  | { readonly state: "forbidden"; readonly service: ServiceName };

/** `GET /agents` (identity), one or more pages joined. */
export interface AgentsAnswer {
  readonly agents: readonly unknown[];
}
/** `GET /policies` (vault). */
export interface PoliciesAnswer {
  readonly grants: readonly unknown[];
}
/** `GET /revocations` (revocation). */
export interface RevocationsAnswer {
  readonly tombstones: readonly unknown[];
  readonly asOf?: unknown;
}

/** The audit log, pulled and checked with `@custos/audit-client/ledger`. */
export type LedgerCheck =
  | {
      readonly ok: true;
      readonly ledger: PulledAuditLedger;
      readonly delegations: readonly CheckedDelegation[];
    }
  | { readonly ok: false; readonly error: PullAuditLedgerError | DelegationAuditError };

/** How fresh the vault's view of revocations is, from the back end. */
export interface RevocationFreshness {
  /** When the vault last confirmed the revocation list. */
  readonly checkedAt: string;
  /** The vault says its view is older than its bound: every call is refused. */
  readonly stale: boolean;
}

export type Health = Readonly<Record<ServiceName, "answering" | "down" | "unknown">>;

// ---------------------------------------------------------------------------
// Reading the answers. Never throws: everything here came over the network.

export interface Agent {
  readonly did: string;
  readonly label: string;
}

const DID = /^did:[a-z0-9]+:[\x21-\x7E]{1,500}$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Agents by DID, labelled by name (or "unnamed · …a1b2"). Entries without a usable DID are skipped. */
export function agentsOf(answer: AgentsAnswer): ReadonlyMap<string, Agent> {
  const agents = new Map<string, Agent>();
  for (const value of answer.agents) {
    if (!isObject(value) || typeof value.did !== "string" || !DID.test(value.did)) continue;
    agents.set(value.did, { did: value.did, label: agentLabel(value.did, value.name) });
  }
  return agents;
}

/** How to show an agent by DID: its name when identity knows it. */
export function labeller(agents: ReadonlyMap<string, Agent> | undefined): (did: string) => string {
  return (did) => agents?.get(did)?.label ?? agentLabel(did);
}

export interface Grant {
  readonly agentDid: string;
  readonly tool: string;
  readonly by: string | undefined;
  readonly at: string | undefined;
}

export function grantsOf(answer: PoliciesAnswer): readonly Grant[] {
  const grants: Grant[] = [];
  for (const value of answer.grants) {
    if (!isObject(value) || typeof value.agentDid !== "string") continue;
    const by = isObject(value.grantedBy) ? plainText(value.grantedBy.name) : undefined;
    grants.push({
      agentDid: value.agentDid,
      tool: plainText(value.tool, 64) ?? "a tool not shown",
      by,
      at: isoTime(value.createdAt),
    });
  }
  return grants;
}

export interface CutOff {
  readonly agentDid: string;
  readonly revokedAt: string;
  readonly reason: string | undefined;
}

/**
 * The revoked agents in `GET /revocations`, decoded, not signature-checked
 * (as `custos status` does: the vault checks every tombstone it acts on, and
 * a forged "revoked" errs on the safe side). One entry that cannot be decoded
 * makes the whole answer unreadable: "nobody cut off" is never answered past
 * an entry that could be anyone's.
 */
export function cutOffsOf(answer: RevocationsAnswer): readonly CutOff[] | undefined {
  const cutOffs: CutOff[] = [];
  for (const tombstone of answer.tombstones) {
    if (typeof tombstone !== "string") return undefined;
    let claims: unknown;
    try {
      claims = JSON.parse(Buffer.from(tombstone.split(".")[0] ?? "", "base64url").toString("utf8"));
    } catch {
      return undefined;
    }
    if (!isObject(claims) || typeof claims.agentDid !== "string") return undefined;
    const revokedAt = isoTime(claims.revokedAt);
    if (revokedAt === undefined) return undefined;
    cutOffs.push({
      agentDid: claims.agentDid,
      revokedAt,
      reason: plainText(claims.reason, 200),
    });
  }
  return cutOffs.sort((a, b) => Date.parse(b.revokedAt) - Date.parse(a.revokedAt));
}

// ---------------------------------------------------------------------------
// Time, in UTC so every viewer and every test reads the same.

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;

export function isoTime(value: unknown): string | undefined {
  return typeof value === "string" && ISO.test(value) && !Number.isNaN(Date.parse(value))
    ? value
    : undefined;
}

/**
 * Whether `time` falls in the last `windowMs` before `now`, edges included:
 * exactly one hour old is still "in the last hour". A time a little ahead of
 * `now` (another service's clock) counts as just now.
 */
export function within(time: string, now: Date, windowMs: number): boolean {
  return now.getTime() - Date.parse(time) <= windowMs;
}

/** "14:02" (UTC); "--:--" for a time that is not ISO. */
export function clock(time: unknown): string {
  const checked = isoTime(time);
  return checked === undefined ? "--:--" : checked.slice(11, 16);
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function day(time: string): string {
  const date = new Date(time);
  return `${date.getUTCDate()} ${MONTHS[date.getUTCMonth()]}`;
}

export function ago(time: string, now: Date): string {
  const seconds = Math.max(0, Math.floor((now.getTime() - Date.parse(time)) / 1000));
  if (seconds < 60) return `${seconds} s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds <= 86_400) return `${Math.floor(seconds / 3600)} h ago`;
  return `on ${day(time)}`;
}

// ---------------------------------------------------------------------------
// The states a panel can be in, shared by every view.

export type Panel<T> =
  | { readonly state: "ok"; readonly data: T }
  | { readonly state: "loading"; readonly text: Escaped }
  /** Red, naming the service; with the last good data, greyed "as of" its time, when there is some. */
  | {
      readonly state: "unreadable";
      readonly tone: "red";
      readonly text: Escaped;
      readonly asOf?: { readonly time: Escaped; readonly data: T };
    }
  | { readonly state: "forbidden"; readonly text: Escaped };

export const CHECKING = escapeHtml("Checking…");

export function forbidden(what: string): Panel<never> {
  return {
    state: "forbidden",
    text: escapeHtml(`Your group cannot see ${what}. Ask whoever runs Custos.`),
  };
}

export function unreadable<T>(
  service: ServiceName,
  lastGood?: { readonly data: T; readonly readAt: string },
): Panel<T> {
  return {
    state: "unreadable",
    tone: "red",
    text: escapeHtml(`The ${service} service is not answering.`),
    ...(lastGood === undefined
      ? {}
      : { asOf: { time: escapeHtml(`as of ${clock(lastGood.readAt)}`), data: lastGood.data } }),
  };
}

/**
 * A panel from one source: `build` turns the answer into view data, or
 * returns undefined when the answer cannot be read (then it is unreadable,
 * never empty). A failed source keeps its last good answer, greyed.
 */
export function panelOf<A, T>(
  source: Source<A>,
  what: string,
  build: (data: A) => T | undefined,
): Panel<T> {
  switch (source.state) {
    case "loading":
      return { state: "loading", text: CHECKING };
    case "forbidden":
      return forbidden(what);
    case "failed": {
      const last = source.lastGood === undefined ? undefined : build(source.lastGood.data);
      return unreadable(
        source.service,
        last === undefined ? undefined : { data: last, readAt: source.lastGood!.readAt },
      );
    }
    case "ok": {
      const data = build(source.data);
      return data === undefined
        ? {
            state: "unreadable",
            tone: "red",
            text: escapeHtml(`The answer about ${what} could not be read.`),
          }
        : { state: "ok", data };
    }
  }
}

/** The DID as a secondary field, or words when it is not plain text. */
export function didText(did: string): Escaped {
  return escapeHtml(plainText(did, 512) ?? "(not shown)");
}

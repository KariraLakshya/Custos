import { REFUSALS, refusalOfRecord } from "@custos/contracts";
import { escapeHtml, type Escaped } from "./escape.js";
import {
  agentsOf,
  ago,
  CHECKING,
  clock,
  cutOffsOf,
  didText,
  isoTime,
  labeller,
  panelOf,
  SERVICES,
  within,
  type AgentsAnswer,
  type Health,
  type LedgerCheck,
  type Panel,
  type RevocationFreshness,
  type RevocationsAnswer,
  type ServiceName,
  type Source,
} from "./inputs.js";
import { chainRoots, ledgerVerdict, revokers, sentenceOf } from "./proof.js";

/**
 * The _Now_ view (dashboard plan, screen 1): "Is anything wrong right now?"
 *
 * Grey is normal, red is a problem (ADR 0022 §6). A refusal or a cut-off is
 * Custos working: grey, and counted. Red is only for a service not answering,
 * out-of-date revocation information, an audit record that does not verify,
 * and a refusal whose catalogue severity is `alarm`.
 */

/** "Recent" on Now (founder, 2026-11-16): one hour for refusals, 24 hours for cut-offs. */
export const REFUSAL_WINDOW_MS = 60 * 60 * 1000;
export const CUT_OFF_WINDOW_MS = 24 * 60 * 60 * 1000;
/** A new cut-off is highlighted this long (it replaces today's toast). */
export const HIGHLIGHT_MS = 10 * 1000;

export interface Problem {
  readonly text: Escaped;
  readonly next: Escaped;
}

export interface CutOffItem {
  readonly agent: Escaped;
  readonly did: Escaped;
  /** "cut off 5 s ago by alice@company.com". */
  readonly text: Escaped;
  readonly reason: Escaped | undefined;
  readonly highlight: boolean;
  readonly tone: "grey";
}

export interface RefusalItem {
  readonly time: Escaped;
  readonly text: Escaped;
  readonly tone: "grey" | "red";
}

export interface NowView {
  readonly headline: {
    readonly tone: "green" | "red" | "grey";
    readonly text: Escaped;
    /** Under "All clear": what was checked. Under a problem count: one line per problem. */
    readonly detail: Escaped | undefined;
    readonly problems: readonly Problem[];
  };
  readonly cutOff: Panel<{
    readonly items: readonly CutOffItem[];
    readonly empty: Escaped | undefined;
  }>;
  readonly refusals: Panel<{
    readonly count: number;
    readonly text: Escaped;
    readonly items: readonly RefusalItem[];
  }>;
  readonly services: readonly {
    readonly name: Escaped;
    readonly tone: "grey" | "red";
    readonly text: Escaped;
  }[];
}

export interface NowInput {
  readonly now: Date;
  readonly health: Health;
  readonly freshness: Source<RevocationFreshness>;
  readonly agents: Source<AgentsAnswer>;
  readonly revocations: Source<RevocationsAnswer>;
  readonly ledger: Source<LedgerCheck>;
}

const problem = (text: string, next: string): Problem => ({
  text: escapeHtml(text),
  next: escapeHtml(next),
});

export function nowView(input: NowInput): NowView {
  const { now } = input;
  const verdict = ledgerVerdict(input.ledger);
  const verified = verdict.kind === "verified" ? verdict.check.ledger : undefined;
  const label = labeller(input.agents.state === "ok" ? agentsOf(input.agents.data) : undefined);
  const problems: Problem[] = [];

  // --- services ---
  const down = new Set<ServiceName>(SERVICES.filter((s) => input.health[s] === "down"));
  for (const source of [input.freshness, input.agents, input.revocations, input.ledger]) {
    if (source.state === "failed") down.add(source.service);
  }
  for (const service of SERVICES.filter((s) => down.has(s))) {
    problems.push(
      problem(
        `The ${service} service is not answering.${service === "audit" ? " Proof cannot be checked." : ""}`,
        `Check that the ${service} service is running.`,
      ),
    );
  }

  // --- revocation freshness ---
  if (input.freshness.state === "ok" && input.freshness.data.stale) {
    const checked = isoTime(input.freshness.data.checkedAt);
    problems.push(
      problem(
        `The vault's list of cut-off agents is out of date${checked === undefined ? "" : ` (last checked ${clock(checked)})`}, so it is refusing every call.`,
        REFUSALS.REVOCATION_STATE_STALE.nextStep,
      ),
    );
  }

  // --- the audit record ---
  if (verdict.kind === "tampered" || verdict.kind === "needs-a-person") {
    problems.push(
      problem(
        `${verdict.kind === "tampered" ? "The audit record was tampered with" : "The audit record needs a person"}: ${verdict.meaning}`,
        verdict.nextStep,
      ),
    );
  } else if (verdict.kind === "cannot-check" && !down.has("audit")) {
    problems.push(
      problem(`The audit record cannot be checked: ${verdict.meaning}`, verdict.nextStep),
    );
  }

  // --- refusals in the last hour ---
  const recentRefusals =
    verified?.records.filter(
      ({ record }) =>
        record.policy.decision === "deny" &&
        isoTime(record.recordedAt) !== undefined &&
        within(record.recordedAt, now, REFUSAL_WINDOW_MS),
    ) ?? [];
  const alarms = new Map<string, { count: number; meaning: string; next: string }>();
  for (const { record } of recentRefusals) {
    const refusal = refusalOfRecord(record);
    if (refusal?.entry.severity !== "alarm") continue;
    const seen = alarms.get(refusal.code);
    alarms.set(refusal.code, {
      count: (seen?.count ?? 0) + 1,
      meaning: refusal.entry.meaning,
      next: refusal.entry.nextStep,
    });
  }
  for (const { count, meaning, next } of alarms.values()) {
    problems.push(
      problem(
        `${count} ${count === 1 ? "call was" : "calls were"} refused in the last hour: ${meaning}`,
        next,
      ),
    );
  }

  // --- the headline ---
  const loading =
    SERVICES.some((s) => input.health[s] === "unknown") ||
    [input.freshness, input.revocations, input.ledger].some((s) => s.state === "loading");
  const freshnessWords =
    input.freshness.state === "ok" && isoTime(input.freshness.data.checkedAt) !== undefined
      ? ` · revocation list checked ${ago(input.freshness.data.checkedAt, now)}`
      : "";
  const unseen = [
    ...(input.freshness.state === "forbidden" ? ["how fresh the revocation list is"] : []),
    ...(input.revocations.state === "forbidden" ? ["cut-off agents"] : []),
    ...(verdict.kind === "forbidden" ? ["the audit record"] : []),
  ];
  const headline: NowView["headline"] =
    problems.length > 0
      ? {
          tone: "red",
          text: escapeHtml(
            `⚠ ${problems.length} ${problems.length === 1 ? "problem needs" : "problems need"} attention`,
          ),
          detail: undefined,
          problems,
        }
      : loading
        ? { tone: "grey", text: CHECKING, detail: undefined, problems }
        : unseen.length > 0
          ? {
              // Never a green "All clear" over data the person cannot see.
              tone: "grey",
              text: escapeHtml("Your group cannot see everything needed to say all is clear."),
              detail: escapeHtml(`It cannot see ${unseen.join(" or ")}. Ask whoever runs Custos.`),
              problems,
            }
          : {
              tone: "green",
              text: escapeHtml("✓ All clear"),
              detail: escapeHtml(`Every service answering${freshnessWords}`),
              problems,
            };

  // --- cut off recently ---
  const by = verified === undefined ? undefined : revokers(verified.records);
  const cutOff = panelOf(input.revocations, "cut-off agents", (answer) => {
    const cutOffs = cutOffsOf(answer);
    if (cutOffs === undefined) return undefined;
    const items = cutOffs
      .filter((c) => within(c.revokedAt, now, CUT_OFF_WINDOW_MS))
      .map((c): CutOffItem => {
        const who = by?.get(c.agentDid);
        return {
          agent: escapeHtml(label(c.agentDid)),
          did: didText(c.agentDid),
          text: escapeHtml(
            `cut off ${ago(c.revokedAt, now)}${who === undefined ? "" : ` by ${who}`}`,
          ),
          reason: c.reason === undefined ? undefined : escapeHtml(`"${c.reason}"`),
          highlight: now.getTime() - Date.parse(c.revokedAt) <= HIGHLIGHT_MS,
          tone: "grey",
        };
      });
    return {
      items,
      empty:
        items.length > 0 ? undefined : escapeHtml("No agent was cut off in the last 24 hours."),
    };
  });

  // --- the refusal panel ---
  const refusals: NowView["refusals"] =
    verdict.kind === "verified"
      ? (() => {
          const roots = chainRoots(verdict.check.ledger.records);
          const items = recentRefusals
            .map(({ seq, record }) => ({ seq, record }))
            .sort((a, b) => b.seq - a.seq)
            .map(({ record }): RefusalItem => ({
              time: escapeHtml(clock(record.recordedAt)),
              text: escapeHtml(sentenceOf(record, label, roots)),
              tone: refusalOfRecord(record)?.entry.severity === "alarm" ? "red" : "grey",
            }));
          return {
            state: "ok",
            data: {
              count: items.length,
              text: escapeHtml(
                items.length === 0
                  ? "Nothing refused in the last hour"
                  : `Refused in the last hour: ${items.length}   (normal, Custos doing its job)`,
              ),
              items,
            },
          };
        })()
      : verdict.kind === "loading"
        ? { state: "loading", text: CHECKING }
        : verdict.kind === "forbidden"
          ? {
              state: "forbidden",
              text: escapeHtml("Your group cannot see refusals. Ask whoever runs Custos."),
            }
          : {
              state: "unreadable",
              tone: "red",
              text: escapeHtml("Refusals cannot be counted until the audit record can be checked."),
            };

  const services = SERVICES.map((service) => ({
    name: escapeHtml(service),
    tone: down.has(service) ? ("red" as const) : ("grey" as const),
    text: escapeHtml(
      down.has(service)
        ? "not answering"
        : input.health[service] === "unknown"
          ? "checking"
          : "answering",
    ),
  }));

  return { headline, cutOff, refusals, services };
}

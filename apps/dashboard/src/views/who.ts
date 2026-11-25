import type { AuditRecord } from "@custos/core";
import { principalLabel } from "@custos/contracts";
import { escapeHtml, joinEscaped, type Escaped } from "./escape.js";
import {
  agentsOf,
  CHECKING,
  clock,
  cutOffsOf,
  day,
  didText,
  grantsOf,
  labeller,
  panelOf,
  type AgentsAnswer,
  type Grant,
  type LedgerCheck,
  type Panel,
  type PoliciesAnswer,
  type RevocationsAnswer,
  type Source,
} from "./inputs.js";
import { ledgerVerdict, revokers } from "./proof.js";

/**
 * The _Who can do what_ view (dashboard plan, screen 2): "Who may do what,
 * and for whom?". Agents by name, the DID as a secondary field. Delegation
 * chains are shown "as used": a hand-off that was never presented is not
 * stored anywhere (ADR 0022 §5), so the column reads "chains in use".
 */

/** One cell that depends on a source that may be missing. */
export type Cell =
  | { readonly state: "ok"; readonly lines: readonly Escaped[] }
  | { readonly state: "loading" | "unreadable" | "forbidden"; readonly text: Escaped };

export interface WhoRow {
  readonly agent: Escaped;
  readonly did: Escaped;
  /** Undefined while the agent is usable; "cut off 20 Nov by alice@company.com" when not. */
  readonly cutOff: Escaped | undefined;
  readonly actingFor: Cell;
  readonly mayUse: Cell;
}

export interface WhoView {
  readonly columns: {
    readonly agent: Escaped;
    readonly actingFor: Escaped;
    readonly mayUse: Escaped;
  };
  /** Usable agents first, cut-off agents at the bottom. */
  readonly table: Panel<{ readonly rows: readonly WhoRow[]; readonly empty: Escaped | undefined }>;
}

export interface WhoInput {
  readonly agents: Source<AgentsAnswer>;
  readonly grants: Source<PoliciesAnswer>;
  readonly revocations: Source<RevocationsAnswer>;
  readonly ledger: Source<LedgerCheck>;
  /** The search box: filters by name, case-insensitive. */
  readonly search?: string;
}

/** A delegated pass, as it was used: the chain and what it covered. */
interface UsedPass {
  readonly chain: string;
  readonly tool: string | undefined;
  readonly action: string;
  readonly until: string | undefined;
}

/** When the last hand-off in a chain runs out, read from the verified evidence. */
function expiryOf(record: AuditRecord): string | undefined {
  const last = record.delegation?.handOffs.at(-1);
  if (last === undefined) return undefined;
  try {
    const claims: unknown = JSON.parse(
      Buffer.from(last.split(".")[0] ?? "", "base64url").toString("utf8"),
    );
    const exp = (claims as { exp?: unknown } | null)?.exp;
    return typeof exp === "number" && Number.isSafeInteger(exp)
      ? new Date(exp * 1000).toISOString()
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Every chain each agent used, from the verified log's issuance entries
 * (they carry the root): "alice@company.com → billing-bot" for helper-bot.
 */
function passesUsed(
  records: readonly { readonly record: AuditRecord }[],
  label: (did: string) => string,
): ReadonlyMap<string, readonly UsedPass[]> {
  const passes = new Map<string, UsedPass[]>();
  for (const { record } of records) {
    if (record.delegation === undefined || record.agentDid === undefined) continue;
    if (record.policy.decision !== "allow") continue;
    const before = record.authorityChain.slice(0, -1).map(label);
    const pass: UsedPass = {
      chain: [principalLabel(record.delegation.root), ...before].join(" → "),
      tool: record.tool,
      action: record.action,
      until: expiryOf(record),
    };
    const list = passes.get(record.agentDid) ?? [];
    if (
      !list.some((p) => p.chain === pass.chain && p.tool === pass.tool && p.action === pass.action)
    ) {
      list.push(pass);
    }
    passes.set(record.agentDid, list);
  }
  return passes;
}

function cellFrom<T>(panel: Panel<T>, build: (data: T) => readonly string[]): Cell {
  switch (panel.state) {
    case "ok":
      return { state: "ok", lines: build(panel.data).map(escapeHtml) };
    case "unreadable":
      return panel.asOf === undefined
        ? { state: "unreadable", text: panel.text }
        : {
            state: "ok",
            lines: [
              ...build(panel.asOf.data).map(escapeHtml),
              joinEscaped(escapeHtml("("), panel.asOf.time, escapeHtml("; could not check now)")),
            ],
          };
    default:
      return { state: panel.state, text: panel.text };
  }
}

export function whoView(input: WhoInput): WhoView {
  const columns = {
    agent: escapeHtml("Agent"),
    actingFor: escapeHtml("Acting for (chains in use)"),
    mayUse: escapeHtml("May use"),
  };
  const grants = panelOf(input.grants, "grants", (answer) => grantsOf(answer));
  const cutOffs = panelOf(input.revocations, "cut-off agents", (answer) => cutOffsOf(answer));
  const verdict = ledgerVerdict(input.ledger);

  const table = panelOf(input.agents, "agents", (answer) => {
    const agents = agentsOf(answer);
    const label = labeller(agents);
    const used =
      verdict.kind === "verified" ? passesUsed(verdict.check.ledger.records, label) : undefined;
    const by = verdict.kind === "verified" ? revokers(verdict.check.ledger.records) : undefined;
    const needle = input.search?.trim().toLowerCase() ?? "";

    const rows = [...agents.values()]
      .filter((agent) => needle === "" || agent.label.toLowerCase().includes(needle))
      .map((agent) => {
        const mine = (all: readonly Grant[]) => all.filter((g) => g.agentDid === agent.did);
        const passes = used?.get(agent.did) ?? [];
        const cut =
          cutOffs.state === "ok" ? cutOffs.data.find((c) => c.agentDid === agent.did) : undefined;

        const actingFor: Cell =
          verdict.kind === "verified"
            ? cellFrom(grants, (all) => [
                ...new Set([
                  ...mine(all).map((g) => g.by ?? "an operator"),
                  ...passes.map((p) => p.chain),
                ]),
              ])
            : verdict.kind === "loading"
              ? { state: "loading", text: CHECKING }
              : verdict.kind === "forbidden"
                ? {
                    state: "forbidden",
                    text: escapeHtml(
                      "Your group cannot see the chains in use. Ask whoever runs Custos.",
                    ),
                  }
                : {
                    state: "unreadable",
                    text: escapeHtml(
                      "Chains cannot be shown until the audit record can be checked.",
                    ),
                  };

        const mayUse: Cell =
          cut !== undefined
            ? { state: "ok", lines: [escapeHtml("no longer usable")] }
            : cellFrom(grants, (all) => [
                ...mine(all).map((g) => {
                  const given = [
                    g.by === undefined ? undefined : `given by ${g.by}`,
                    g.at === undefined ? undefined : day(g.at),
                  ]
                    .filter((part) => part !== undefined)
                    .join(", ");
                  return given === "" ? g.tool : `${g.tool} (${given})`;
                }),
                ...passes.map(
                  (p) =>
                    `${p.tool ?? "a tool"}: ${p.action} (passed on${p.until === undefined ? "" : `, until ${clock(p.until)}`})`,
                ),
              ]);

        return {
          row: {
            agent: escapeHtml(agent.label),
            did: didText(agent.did),
            cutOff:
              cut !== undefined
                ? escapeHtml(
                    `cut off ${day(cut.revokedAt)}${by?.has(agent.did) === true ? ` by ${by.get(agent.did)}` : ""}`,
                  )
                : cutOffs.state === "ok"
                  ? undefined
                  : escapeHtml("could not check whether it is cut off"),
            actingFor:
              cut !== undefined && actingFor.state === "ok" && actingFor.lines.length === 0
                ? { state: "ok" as const, lines: [escapeHtml("—")] }
                : actingFor,
            mayUse,
          } satisfies WhoRow,
          bottom: cut !== undefined,
        };
      });

    const ordered = [...rows.filter((r) => !r.bottom), ...rows.filter((r) => r.bottom)].map(
      (r) => r.row,
    );
    return {
      rows: ordered,
      empty:
        ordered.length > 0
          ? undefined
          : escapeHtml(needle === "" ? "No agents yet." : "No agent has that name."),
    };
  });

  return { columns, table };
}

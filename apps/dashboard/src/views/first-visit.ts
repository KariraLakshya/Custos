import { escapeHtml, type Escaped } from "./escape.js";
import {
  CHECKING,
  cutOffsOf,
  forbidden,
  grantsOf,
  unreadable,
  type AgentsAnswer,
  type LedgerCheck,
  type Panel,
  type PoliciesAnswer,
  type RevocationsAnswer,
  type Source,
} from "./inputs.js";
import { ledgerVerdict } from "./proof.js";

/**
 * The first visit (dashboard plan, founder 2026-11-15): someone with no
 * agents sees a start screen walking through the lifecycle, never empty
 * tables. It is shown only when the agent read succeeded and was empty: "no
 * agents" must never hide "cannot see agents" or "identity not answering".
 */

export interface Step {
  readonly number: 1 | 2 | 3 | 4;
  readonly title: Escaped;
  /** Shown, never run: the page is read-only. */
  readonly command: Escaped;
  readonly done: boolean;
}

/** Made-up data, labelled EXAMPLE on the panel itself and never mixed into a real view. */
export interface ExamplePanel {
  readonly label: "EXAMPLE";
  readonly faded: true;
  readonly lines: readonly Escaped[];
}

export type Start =
  /** No agents yet: the start screen in place of all three views. */
  | {
      readonly screen: "start";
      readonly welcome: Escaped;
      readonly steps: readonly Step[];
      readonly example: ExamplePanel;
    }
  /** At least one agent: the normal views, with the checklist as a strip until step 4 or dismissed. */
  | { readonly screen: "views"; readonly strip: readonly Step[] | undefined }
  /** The agent read is loading, refused or failed: that state, never the start screen. */
  | { readonly screen: "blocked"; readonly panel: Panel<never> };

export interface StartInput {
  readonly person: string;
  readonly agents: Source<AgentsAnswer>;
  readonly grants: Source<PoliciesAnswer>;
  readonly revocations: Source<RevocationsAnswer>;
  readonly ledger: Source<LedgerCheck>;
  readonly dismissed?: boolean;
}

const EXAMPLE: ExamplePanel = {
  label: "EXAMPLE",
  faded: true,
  lines: [
    "✓ All clear",
    "Cut off recently: example-bot, cut off 5 s ago by you",
    "Refused in the last hour: 1   (normal, Custos doing its job)",
  ].map(escapeHtml),
};

function steps(input: StartInput, agentCount: number): readonly Step[] {
  const granted = input.grants.state === "ok" && grantsOf(input.grants.data).length > 0;
  const verdict = ledgerVerdict(input.ledger);
  const called =
    verdict.kind === "verified" &&
    verdict.check.ledger.records.some(
      ({ record }) => record.principal === undefined && record.policy.decision === "allow",
    );
  const cut =
    input.revocations.state === "ok" && (cutOffsOf(input.revocations.data)?.length ?? 0) > 0;
  const step = (number: Step["number"], title: string, command: string, done: boolean): Step => ({
    number,
    title: escapeHtml(title),
    command: escapeHtml(command),
    done,
  });
  return [
    step(1, "Register an agent", "custos register --name billing-bot", agentCount > 0),
    step(2, "Give it a tool", "custos grant mock-database --to <agent id>", granted),
    step(3, "Let it make a call", "custos use mock-database query", called),
    step(4, "Cut it off", "custos revoke <agent id>", cut),
  ];
}

export function startView(input: StartInput): Start {
  const agents = input.agents;
  if (agents.state === "loading") {
    return { screen: "blocked", panel: { state: "loading", text: CHECKING } };
  }
  if (agents.state === "forbidden") return { screen: "blocked", panel: forbidden("agents") };
  if (agents.state === "failed") return { screen: "blocked", panel: unreadable(agents.service) };
  const count = agents.data.agents.length;
  if (count === 0) {
    return {
      screen: "start",
      welcome: escapeHtml(
        `Welcome, ${input.person}. You have no agents yet. Four steps, about five minutes:`,
      ),
      steps: steps(input, 0),
      example: EXAMPLE,
    };
  }
  const all = steps(input, count);
  return {
    screen: "views",
    strip: input.dismissed === true || all.every((s) => s.done) ? undefined : all,
  };
}

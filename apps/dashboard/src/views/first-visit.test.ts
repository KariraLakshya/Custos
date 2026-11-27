import { describe, expect, it } from "vitest";
import { startView, type StartInput } from "./first-visit.js";
import { nowView } from "./now.js";
import { proofView } from "./proof.js";
import { checkLedger, loadFixture, ok } from "./test-fixtures.js";
import { whoView } from "./who.js";

const clean = loadFixture("clean");
const cleanLedger = ok(await checkLedger(clean));
const empty = ok({ agents: [] });

const base: StartInput = {
  person: "alice@company.com",
  agents: empty,
  grants: ok({ grants: [] }),
  revocations: ok({ tombstones: [] }),
  ledger: ok({
    ok: true,
    ledger: {
      records: [],
      headSeq: 0,
      unsealedCount: 0,
      log: "l",
      publishedKey: "z",
      servedSeal: null,
    },
    delegations: [],
  }),
};

describe("first visit", () => {
  it("an empty, successful agent read shows the start screen, with the four commands", () => {
    const view = startView(base);
    if (view.screen !== "start") throw new Error("expected the start screen");
    expect(view.welcome).toBe(
      "Welcome, alice@company.com. You have no agents yet. Four steps, about five minutes:",
    );
    expect(view.steps.map((s) => `${s.number} ${s.title}: ${s.command} ${s.done}`)).toEqual([
      "1 Register an agent: custos register --name billing-bot false",
      "2 Give it a tool: custos grant mock-database --to &lt;agent id&gt; false",
      "3 Let it make a call: custos use mock-database query false",
      "4 Cut it off: custos revoke &lt;agent id&gt; false",
    ]);
    expect(view.example.label).toBe("EXAMPLE");
    expect(view.example.faded).toBe(true);
  });

  it("a refused agent read shows that state, never 'no agents'", () => {
    expect(startView({ ...base, agents: { state: "forbidden", service: "identity" } })).toEqual({
      screen: "blocked",
      panel: { state: "forbidden", text: "Your group cannot see agents. Ask whoever runs Custos." },
    });
  });

  it("a failed agent read shows the service not answering, never 'no agents'", () => {
    expect(startView({ ...base, agents: { state: "failed", service: "identity" } })).toEqual({
      screen: "blocked",
      panel: { state: "unreadable", tone: "red", text: "The identity service is not answering." },
    });
  });

  it("loading shows Checking…", () => {
    expect(startView({ ...base, agents: { state: "loading" } })).toEqual({
      screen: "blocked",
      panel: { state: "loading", text: "Checking…" },
    });
  });

  it("after the first agent, the normal views appear with the checklist as a strip", () => {
    const view = startView({
      ...base,
      agents: ok(clean.agents),
      grants: ok(clean.policies),
      ledger: { state: "loading" },
    });
    if (view.screen !== "views") throw new Error("expected the views");
    expect(view.strip?.map((s) => s.done)).toEqual([true, true, false, false]);
  });

  it("each step ticks itself from the real reads; all four ticked, the strip goes", () => {
    const view = startView({
      ...base,
      agents: ok(clean.agents),
      grants: ok(clean.policies),
      revocations: ok(clean.revocations),
      ledger: cleanLedger,
    });
    expect(view).toEqual({ screen: "views", strip: undefined });
  });

  it("a dismissed checklist stays gone", () => {
    expect(startView({ ...base, agents: ok(clean.agents), dismissed: true })).toEqual({
      screen: "views",
      strip: undefined,
    });
  });

  it("the example never appears inside a real view", async () => {
    const health = {
      identity: "answering",
      vault: "answering",
      revocation: "answering",
      audit: "answering",
    } as const;
    const views = [
      nowView({
        now: new Date(clean.now),
        health,
        freshness: ok({ checkedAt: clean.now, stale: false }),
        agents: empty,
        revocations: ok({ tombstones: [] }),
        ledger: base.ledger,
      }),
      whoView({
        agents: empty,
        grants: base.grants,
        revocations: base.revocations,
        ledger: base.ledger,
      }),
      proofView({ ledger: base.ledger, agents: empty }),
    ];
    for (const view of views) {
      expect(JSON.stringify(view)).not.toMatch(/EXAMPLE|example-bot/);
    }
  });
});

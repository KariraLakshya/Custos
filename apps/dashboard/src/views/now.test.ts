import { describe, expect, it } from "vitest";
import type { AuditRecord } from "@custos/core";
import type { Health, LedgerCheck, RevocationsAnswer, Source } from "./inputs.js";
import {
  nowView,
  REFUSAL_WINDOW_MS,
  CUT_OFF_WINDOW_MS,
  HIGHLIGHT_MS,
  type NowInput,
} from "./now.js";
import { checkLedger, loadFixture, ok, type Fixture } from "./test-fixtures.js";

const BILLING = "did:web:localhost%3A4001:agents:6f1d2c3b-0000-4000-8000-00000000a1b2";
const ALL_UP: Health = {
  identity: "answering",
  vault: "answering",
  revocation: "answering",
  audit: "answering",
};

async function inputFor(fixture: Fixture, overrides: Partial<NowInput> = {}): Promise<NowInput> {
  return {
    now: new Date(fixture.now),
    health: ALL_UP,
    freshness: ok({ checkedAt: "2026-11-20T14:09:57.000Z", stale: false }),
    agents: ok(fixture.agents),
    revocations: ok(fixture.revocations),
    ledger: ok(await checkLedger(fixture)),
    ...overrides,
  };
}

const clean = loadFixture("clean");
const cleanInput = await inputFor(clean);

function tombstone(claims: Record<string, unknown>): string {
  return `${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
}

function verifiedWith(records: AuditRecord[]): Source<LedgerCheck> {
  return ok({
    ok: true,
    ledger: {
      records: records.map((record, i) => ({ seq: i + 1, record })),
      headSeq: records.length,
      unsealedCount: records.length,
      log: "did:web:localhost%3A4004",
      publishedKey: "z",
      servedSeal: null,
    },
    delegations: [],
  });
}

function refusal(recordedAt: string, rule = "agent-tool-allowlist"): AuditRecord {
  return {
    agentDid: BILLING,
    authorityChain: [BILLING],
    tool: "stripe",
    action: "list-customers",
    dataCategories: [],
    policy: { rule, decision: "deny" },
    recordedAt,
  };
}

describe("Now, against the recorded fixtures", () => {
  it("clean: All clear, in green, with what was checked", () => {
    const view = nowView(cleanInput);
    expect(view.headline).toEqual({
      tone: "green",
      text: "✓ All clear",
      detail: "Every service answering · revocation list checked 3 s ago",
      problems: [],
    });
  });

  it("clean: the cut-off line names the agent, who did it, when and why, in grey", () => {
    const view = nowView(cleanInput);
    expect(view.cutOff).toEqual({
      state: "ok",
      data: {
        items: [
          {
            agent: "billing-bot",
            did: BILLING,
            text: "cut off 5 min ago by alice@company.com",
            reason: "&quot;key leaked&quot;",
            highlight: false,
            tone: "grey",
          },
        ],
        empty: undefined,
      },
    });
  });

  it("clean: refusals are grey and counted, newest first, with the catalogue's meaning", () => {
    const view = nowView(cleanInput);
    if (view.refusals.state !== "ok") throw new Error("expected refusals");
    expect(view.refusals.data.count).toBe(2);
    expect(view.refusals.data.text).toBe(
      "Refused in the last hour: 2   (normal, Custos doing its job)",
    );
    expect(view.refusals.data.items).toEqual([
      {
        time: "14:06",
        text: "billing-bot asked to use mock-database (query): refused. This agent, or an agent it is acting for, has been cut off from every tool.",
        tone: "grey",
      },
      {
        time: "14:03",
        text: "billing-bot asked to use stripe (list-customers): refused. This agent has not been given this tool.",
        tone: "grey",
      },
    ]);
  });

  it("clean: every service answering, none red", () => {
    expect(nowView(cleanInput).services.map((s) => `${s.name}:${s.tone}:${s.text}`)).toEqual([
      "identity:grey:answering",
      "vault:grey:answering",
      "revocation:grey:answering",
      "audit:grey:answering",
    ]);
  });

  it("tampered: red, one problem, and refusals are not counted from a log that did not verify", async () => {
    const view = nowView(await inputFor(loadFixture("tampered")));
    expect(view.headline.tone).toBe("red");
    expect(view.headline.text).toBe("⚠ 1 problem needs attention");
    expect(view.headline.problems[0]!.text).toBe(
      "The audit record was tampered with: Entry #4 does not match its seal.",
    );
    expect(view.refusals).toEqual({
      state: "unreadable",
      tone: "red",
      text: "Refusals cannot be counted until the audit record can be checked.",
    });
  });

  it("tampered: the cut-off is still shown, without a 'by' the log cannot prove", async () => {
    const view = nowView(await inputFor(loadFixture("tampered")));
    if (view.cutOff.state !== "ok") throw new Error("expected cut-offs");
    expect(view.cutOff.data.items[0]!.text).toBe("cut off 5 min ago");
  });

  it("truncated: red", async () => {
    const view = nowView(await inputFor(loadFixture("truncated")));
    expect(view.headline.tone).toBe("red");
    expect(view.headline.problems[0]!.text).toContain("The newest entries were deleted");
  });

  it("delegated: All clear, nothing cut off, nothing refused", async () => {
    const view = nowView(await inputFor(loadFixture("delegated")));
    expect(view.headline.text).toBe("✓ All clear");
    expect(view.cutOff).toEqual({
      state: "ok",
      data: { items: [], empty: "No agent was cut off in the last 24 hours." },
    });
    if (view.refusals.state !== "ok") throw new Error("expected refusals");
    expect(view.refusals.data.text).toBe("Nothing refused in the last hour");
  });
});

describe("grey versus red", () => {
  it("a refusal never produces red", () => {
    const view = nowView({
      ...cleanInput,
      ledger: verifiedWith([refusal("2026-11-20T14:09:00.000Z")]),
    });
    expect(view.headline.tone).toBe("green");
    if (view.refusals.state !== "ok") throw new Error("expected refusals");
    expect(view.refusals.data.items[0]!.tone).toBe("grey");
  });

  it("every normal-severity rule the vault records stays grey", () => {
    const rules = [
      "agent-tool-allowlist",
      "revocation",
      "revocation-state-unknown",
      "token-scope",
      "unknown-tool",
      "connector",
      "delegation:mock-database",
      "control-plane-scope:agents:revoke",
      "something-new",
    ];
    const view = nowView({
      ...cleanInput,
      ledger: verifiedWith(rules.map((rule) => refusal("2026-11-20T14:09:00.000Z", rule))),
    });
    expect(view.headline.tone).toBe("green");
    if (view.refusals.state !== "ok") throw new Error("expected refusals");
    expect(view.refusals.data.count).toBe(rules.length);
    expect(view.refusals.data.items.every((i) => i.tone === "grey")).toBe(true);
  });

  it("a stale revocation list always produces red", () => {
    const view = nowView({
      ...cleanInput,
      freshness: ok({ checkedAt: "2026-11-20T14:08:00.000Z", stale: true }),
    });
    expect(view.headline.tone).toBe("red");
    expect(view.headline.problems).toEqual([
      {
        text: "The vault&#39;s list of cut-off agents is out of date (last checked 14:08), so it is refusing every call.",
        next: "Check that the revocation service is running; the vault catches up within seconds once it is.",
      },
    ]);
  });

  it("a refusal recorded because the list was stale is red, and counted as a problem", () => {
    const view = nowView({
      ...cleanInput,
      ledger: verifiedWith([
        refusal("2026-11-20T14:09:00.000Z", "revocation-state-stale"),
        refusal("2026-11-20T14:09:01.000Z", "revocation-state-stale"),
      ]),
    });
    expect(view.headline.tone).toBe("red");
    expect(view.headline.problems[0]!.text).toBe(
      "2 calls were refused in the last hour: The vault&#39;s list of cut-off agents is out of date, so it is refusing every call until it catches up.",
    );
    if (view.refusals.state !== "ok") throw new Error("expected refusals");
    expect(view.refusals.data.items.map((i) => i.tone)).toEqual(["red", "red"]);
  });

  it("an alarm refusal older than an hour is not a problem now", () => {
    const view = nowView({
      ...cleanInput,
      ledger: verifiedWith([refusal("2026-11-20T13:00:00.000Z", "revocation-state-stale")]),
    });
    expect(view.headline.tone).toBe("green");
  });

  it("a stale list with no time given is still red", () => {
    const view = nowView({ ...cleanInput, freshness: ok({ checkedAt: "soon", stale: true }) });
    expect(view.headline.problems[0]!.text).toBe(
      "The vault&#39;s list of cut-off agents is out of date, so it is refusing every call.",
    );
  });

  it("a cut-off is grey", () => {
    const view = nowView(cleanInput);
    if (view.cutOff.state !== "ok") throw new Error("expected cut-offs");
    expect(view.cutOff.data.items.every((i) => i.tone === "grey")).toBe(true);
    expect(view.headline.tone).toBe("green");
  });

  it("a seal key the dashboard did not pin needs a person, in red", async () => {
    const other = loadFixture("delegated").didDocuments.identity.verificationMethod[0]!;
    const view = nowView({
      ...cleanInput,
      ledger: ok(await checkLedger(clean, { trustedKey: other.publicKeyMultibase })),
    });
    expect(view.headline.tone).toBe("red");
    expect(view.headline.problems[0]!.text).toMatch(/^The audit record needs a person: /);
  });
});

describe("each source failing alone", () => {
  it("a service down is red, names the service and its next step", () => {
    const view = nowView({ ...cleanInput, health: { ...ALL_UP, revocation: "down" } });
    expect(view.headline.problems).toEqual([
      {
        text: "The revocation service is not answering.",
        next: "Check that the revocation service is running.",
      },
    ]);
    expect(view.services.find((s) => s.name === "revocation")).toEqual({
      name: "revocation",
      tone: "red",
      text: "not answering",
    });
  });

  it("the audit service down says Proof cannot be checked, once", () => {
    const view = nowView({
      ...cleanInput,
      health: { ...ALL_UP, audit: "down" },
      ledger: { state: "failed", service: "audit" },
    });
    expect(view.headline.problems.map((p) => p.text)).toEqual([
      "The audit service is not answering. Proof cannot be checked.",
    ]);
    expect(view.refusals.state).toBe("unreadable");
  });

  it("the audit log failing to read, with health not yet showing it, is still red", () => {
    const view = nowView({
      ...cleanInput,
      ledger: ok({ ok: false, error: { code: "BAD_RESPONSE", reason: "x", status: 500 } }),
    });
    expect(view.headline.tone).toBe("red");
    expect(view.headline.problems[0]!.text).toMatch(/^The audit record cannot be checked/);
  });

  it("the revocation list not readable: red, never 'nobody cut off'; the last good list greyed", () => {
    const failed: Source<RevocationsAnswer> = {
      state: "failed",
      service: "revocation",
      lastGood: { data: clean.revocations, readAt: "2026-11-20T14:02:00.000Z" },
    };
    const view = nowView({ ...cleanInput, revocations: failed });
    expect(view.headline.tone).toBe("red");
    expect(view.cutOff.state).toBe("unreadable");
    if (view.cutOff.state !== "unreadable") throw new Error("expected unreadable");
    expect(view.cutOff.text).toBe("The revocation service is not answering.");
    expect(view.cutOff.asOf?.time).toBe("as of 14:02");
    expect(view.cutOff.asOf?.data.items).toHaveLength(1);

    const noLastGood = nowView({
      ...cleanInput,
      revocations: { state: "failed", service: "revocation" },
    });
    expect(noLastGood.cutOff).toEqual({
      state: "unreadable",
      tone: "red",
      text: "The revocation service is not answering.",
    });
  });

  it("a revocation list with an entry that cannot be read is unreadable, not empty", () => {
    for (const tombstones of [["not base64 json"], [42], [tombstone({ agentDid: BILLING })]]) {
      const view = nowView({ ...cleanInput, revocations: ok({ tombstones }) });
      expect(view.cutOff).toEqual({
        state: "unreadable",
        tone: "red",
        text: "The answer about cut-off agents could not be read.",
      });
    }
  });

  it("the identity service down: red, and agents fall back to unnamed", () => {
    const view = nowView({ ...cleanInput, agents: { state: "failed", service: "identity" } });
    expect(view.headline.problems.map((p) => p.text)).toEqual([
      "The identity service is not answering.",
    ]);
    if (view.cutOff.state !== "ok") throw new Error("expected cut-offs");
    expect(view.cutOff.data.items[0]!.agent).toBe("unnamed · …a1b2");
  });

  it("freshness not readable: the vault is red", () => {
    const view = nowView({ ...cleanInput, freshness: { state: "failed", service: "vault" } });
    expect(view.headline.problems.map((p) => p.text)).toEqual([
      "The vault service is not answering.",
    ]);
  });
});

describe("a missing scope and loading", () => {
  it("a group without revocations:read or audit:read is told so, in grey words, not red", () => {
    const view = nowView({
      ...cleanInput,
      revocations: { state: "forbidden", service: "revocation" },
      ledger: { state: "forbidden", service: "audit" },
    });
    expect(view.cutOff).toEqual({
      state: "forbidden",
      text: "Your group cannot see cut-off agents. Ask whoever runs Custos.",
    });
    expect(view.refusals).toEqual({
      state: "forbidden",
      text: "Your group cannot see refusals. Ask whoever runs Custos.",
    });
    expect(view.headline).toEqual({
      tone: "grey",
      text: "Your group cannot see everything needed to say all is clear.",
      detail: "It cannot see cut-off agents or the audit record. Ask whoever runs Custos.",
      problems: [],
    });
  });

  it("a missing scope is never shown as All clear, and never red", () => {
    for (const overrides of [
      { freshness: { state: "forbidden", service: "vault" } } as const,
      { revocations: { state: "forbidden", service: "revocation" } } as const,
      { ledger: { state: "forbidden", service: "audit" } } as const,
      {
        ledger: ok<LedgerCheck>({
          ok: false,
          error: { code: "BAD_RESPONSE", reason: "x", status: 401 },
        }),
      },
    ]) {
      const view = nowView({ ...cleanInput, ...overrides });
      expect(view.headline.tone).toBe("grey");
      expect(view.headline.text).not.toContain("All clear");
    }
  });

  it("a problem still shows red when a scope is also missing", () => {
    const view = nowView({
      ...cleanInput,
      health: { ...ALL_UP, vault: "down" },
      ledger: { state: "forbidden", service: "audit" },
    });
    expect(view.headline.tone).toBe("red");
  });

  it("loading: Checking… in place of the headline and panels, never empty tables", () => {
    const view = nowView({
      now: new Date(clean.now),
      health: { identity: "unknown", vault: "unknown", revocation: "unknown", audit: "unknown" },
      freshness: { state: "loading" },
      agents: { state: "loading" },
      revocations: { state: "loading" },
      ledger: { state: "loading" },
    });
    expect(view.headline).toEqual({
      tone: "grey",
      text: "Checking…",
      detail: undefined,
      problems: [],
    });
    expect(view.cutOff).toEqual({ state: "loading", text: "Checking…" });
    expect(view.refusals).toEqual({ state: "loading", text: "Checking…" });
    expect(view.services.every((s) => s.text === "checking")).toBe(true);
  });

  it("a problem found while other sources load is shown at once", () => {
    const view = nowView({
      ...cleanInput,
      health: { ...ALL_UP, identity: "unknown", vault: "down" },
    });
    expect(view.headline.tone).toBe("red");
  });

  it("All clear without a readable freshness time says only what it knows", () => {
    const view = nowView({ ...cleanInput, freshness: ok({ checkedAt: "x", stale: false }) });
    expect(view.headline.detail).toBe("Every service answering");
  });
});

describe("the time windows, at their edges", () => {
  const now = new Date("2026-11-20T15:00:00.000Z");
  const before = (ms: number) => new Date(now.getTime() - ms).toISOString();

  it("a refusal exactly one hour old is in the last hour; a millisecond older is not", () => {
    const view = nowView({
      ...cleanInput,
      now,
      ledger: verifiedWith([
        refusal(before(REFUSAL_WINDOW_MS + 1)),
        refusal(before(REFUSAL_WINDOW_MS)),
      ]),
    });
    if (view.refusals.state !== "ok") throw new Error("expected refusals");
    expect(view.refusals.data.count).toBe(1);
  });

  it("a refusal a little ahead of this clock counts as just now", () => {
    const view = nowView({ ...cleanInput, now, ledger: verifiedWith([refusal(before(-2000))]) });
    if (view.refusals.state !== "ok") throw new Error("expected refusals");
    expect(view.refusals.data.count).toBe(1);
  });

  it("a refusal with an unreadable time is not counted as recent", () => {
    const view = nowView({ ...cleanInput, now, ledger: verifiedWith([refusal("yesterday")]) });
    if (view.refusals.state !== "ok") throw new Error("expected refusals");
    expect(view.refusals.data.count).toBe(0);
  });

  const cutOffAt = (revokedAt: string) =>
    ok({ tombstones: [tombstone({ agentDid: BILLING, statusListIndex: 0, revokedAt })] });

  const noLog = verifiedWith([]);

  it("a cut-off exactly 24 hours old is recent; a millisecond older is not", () => {
    const at24 = nowView({
      ...cleanInput,
      now,
      revocations: cutOffAt(before(CUT_OFF_WINDOW_MS)),
      ledger: noLog,
    });
    const past = nowView({
      ...cleanInput,
      now,
      revocations: cutOffAt(before(CUT_OFF_WINDOW_MS + 1)),
      ledger: noLog,
    });
    if (at24.cutOff.state !== "ok" || past.cutOff.state !== "ok") throw new Error("expected ok");
    expect(at24.cutOff.data.items).toHaveLength(1);
    expect(at24.cutOff.data.items[0]!.text).toBe("cut off 24 h ago");
    expect(past.cutOff.data.items).toHaveLength(0);
  });

  it("a new cut-off is highlighted for 10 seconds, edge included", () => {
    const at10 = nowView({
      ...cleanInput,
      now,
      revocations: cutOffAt(before(HIGHLIGHT_MS)),
      ledger: noLog,
    });
    const at11 = nowView({
      ...cleanInput,
      now,
      revocations: cutOffAt(before(HIGHLIGHT_MS + 1)),
      ledger: noLog,
    });
    if (at10.cutOff.state !== "ok" || at11.cutOff.state !== "ok") throw new Error("expected ok");
    expect(at10.cutOff.data.items[0]!.highlight).toBe(true);
    expect(at10.cutOff.data.items[0]!.text).toBe("cut off 10 s ago");
    expect(at11.cutOff.data.items[0]!.highlight).toBe(false);
  });

  it("cut-offs are newest first, and an hour or more reads in hours", () => {
    const view = nowView({
      ...cleanInput,
      now,
      ledger: noLog,
      revocations: ok({
        tombstones: [
          tombstone({
            agentDid: "did:web:x:agents:old1",
            statusListIndex: 1,
            revokedAt: before(2 * 3_600_000),
          }),
          tombstone({ agentDid: BILLING, statusListIndex: 0, revokedAt: before(5000) }),
        ],
      }),
    });
    if (view.cutOff.state !== "ok") throw new Error("expected ok");
    expect(view.cutOff.data.items.map((i) => i.text)).toEqual([
      "cut off 5 s ago",
      "cut off 2 h ago",
    ]);
  });
});

describe("escaping", () => {
  it("a <script> revocation reason is shown as text", () => {
    const view = nowView({
      ...cleanInput,
      revocations: ok({
        tombstones: [
          tombstone({
            agentDid: BILLING,
            statusListIndex: 0,
            revokedAt: "2026-11-20T14:05:00.000Z",
            reason: "<script>alert(1)</script>",
          }),
        ],
      }),
    });
    if (view.cutOff.state !== "ok") throw new Error("expected ok");
    expect(view.cutOff.data.items[0]!.reason).toBe(
      "&quot;&lt;script&gt;alert(1)&lt;/script&gt;&quot;",
    );
  });

  it("a <script> agent name shows as unnamed, and nothing in the view holds a raw <", () => {
    const agents = ok({ agents: [{ did: BILLING, name: "<script>alert(1)</script>" }] });
    const view = nowView({ ...cleanInput, agents });
    if (view.cutOff.state !== "ok") throw new Error("expected ok");
    expect(view.cutOff.data.items[0]!.agent).toBe("unnamed · …a1b2");
    expect(JSON.stringify(view)).not.toMatch(/<|>/);
  });

  it("a <script> operator name in the log is escaped in the cut-off line", () => {
    const revoke: AuditRecord = {
      principal: { kind: "operator", id: "k", name: "<b>mallory</b>" },
      agentDid: BILLING,
      authorityChain: [],
      action: "agents.revoke",
      dataCategories: [],
      policy: { rule: "control-plane-scope:agents:revoke", decision: "allow" },
      recordedAt: "2026-11-20T14:05:00.000Z",
    };
    const view = nowView({ ...cleanInput, ledger: verifiedWith([revoke]) });
    if (view.cutOff.state !== "ok") throw new Error("expected ok");
    expect(view.cutOff.data.items[0]!.text).toBe("cut off 5 min ago by &lt;b&gt;mallory&lt;/b&gt;");
  });
});

import { describe, expect, it } from "vitest";
import type { PoliciesAnswer, Source } from "./inputs.js";
import { checkLedger, loadFixture, ok, type Fixture } from "./test-fixtures.js";
import { whoView, type WhoInput, type WhoRow } from "./who.js";

const BILLING = "did:web:localhost%3A4001:agents:6f1d2c3b-0000-4000-8000-00000000a1b2";
const HELPER = "did:web:localhost%3A4001:agents:6f1d2c3b-0000-4000-8000-00000000c3d4";

async function inputFor(fixture: Fixture, overrides: Partial<WhoInput> = {}): Promise<WhoInput> {
  return {
    agents: ok(fixture.agents),
    grants: ok(fixture.policies),
    revocations: ok(fixture.revocations),
    ledger: ok(await checkLedger(fixture)),
    ...overrides,
  };
}

const clean = loadFixture("clean");
const delegated = loadFixture("delegated");
const delegatedInput = await inputFor(delegated);

function rows(input: WhoInput): readonly WhoRow[] {
  const view = whoView(input);
  if (view.table.state !== "ok") throw new Error(`expected rows, got ${view.table.state}`);
  return view.table.data.rows;
}

describe("Who can do what, against the recorded fixtures", () => {
  it("names the columns, and says chains are the ones in use", () => {
    expect(whoView(delegatedInput).columns).toEqual({
      agent: "Agent",
      actingFor: "Acting for (chains in use)",
      mayUse: "May use",
    });
  });

  it("delegated: the chain reads person → agent → agent, shown as used", () => {
    expect(rows(delegatedInput)).toEqual([
      {
        agent: "billing-bot",
        did: BILLING,
        cutOff: undefined,
        actingFor: { state: "ok", lines: ["alice@company.com"] },
        mayUse: { state: "ok", lines: ["mock-database (given by alice@company.com, 20 Nov)"] },
      },
      {
        agent: "helper-bot",
        did: HELPER,
        cutOff: undefined,
        actingFor: { state: "ok", lines: ["alice@company.com → billing-bot"] },
        mayUse: { state: "ok", lines: ["mock-database: query (passed on, until 15:04)"] },
      },
    ]);
  });

  it("clean: a cut-off agent is no longer usable, with when and by whom", async () => {
    expect(rows(await inputFor(clean))).toEqual([
      {
        agent: "billing-bot",
        did: BILLING,
        cutOff: "cut off 20 Nov by alice@company.com",
        actingFor: { state: "ok", lines: ["alice@company.com"] },
        mayUse: { state: "ok", lines: ["no longer usable"] },
      },
    ]);
  });

  it("cut-off agents sit at the bottom", async () => {
    const revoked = await inputFor(clean);
    const both = whoView({
      ...delegatedInput,
      revocations: revoked.revocations,
    });
    if (both.table.state !== "ok") throw new Error("expected rows");
    expect(both.table.data.rows.map((r) => r.agent)).toEqual(["helper-bot", "billing-bot"]);
    expect(both.table.data.rows[1]!.cutOff).toBe("cut off 20 Nov");
  });

  it("tampered: chains are not shown from a log that did not verify", async () => {
    const [row] = rows(await inputFor(loadFixture("tampered")));
    expect(row!.actingFor).toEqual({
      state: "unreadable",
      text: "Chains cannot be shown until the audit record can be checked.",
    });
    expect(row!.cutOff).toBe("cut off 20 Nov");
  });

  it("the search box filters by name, ignoring case", () => {
    expect(rows({ ...delegatedInput, search: "  HELPER " }).map((r) => r.agent)).toEqual([
      "helper-bot",
    ]);
    const none = whoView({ ...delegatedInput, search: "nobody" });
    if (none.table.state !== "ok") throw new Error("expected rows");
    expect(none.table.data.empty).toBe("No agent has that name.");
  });
});

describe("Who can do what, each source alone", () => {
  it("a group without policies:read sees 'your group cannot see grants'", () => {
    const [row] = rows({ ...delegatedInput, grants: { state: "forbidden", service: "vault" } });
    expect(row!.mayUse).toEqual({
      state: "forbidden",
      text: "Your group cannot see grants. Ask whoever runs Custos.",
    });
  });

  it("a group without agents:read sees that, never an empty table", () => {
    expect(
      whoView({ ...delegatedInput, agents: { state: "forbidden", service: "identity" } }).table,
    ).toEqual({
      state: "forbidden",
      text: "Your group cannot see agents. Ask whoever runs Custos.",
    });
  });

  it("a group without audit:read is told it cannot see the chains", () => {
    const [row] = rows({ ...delegatedInput, ledger: { state: "forbidden", service: "audit" } });
    expect(row!.actingFor).toEqual({
      state: "forbidden",
      text: "Your group cannot see the chains in use. Ask whoever runs Custos.",
    });
  });

  it("the vault not answering: grants could not be checked, never 'no tools'", () => {
    const [row] = rows({ ...delegatedInput, grants: { state: "failed", service: "vault" } });
    expect(row!.mayUse).toEqual({
      state: "unreadable",
      text: "The vault service is not answering.",
    });
  });

  it("the vault not answering, with a last good answer: shown, marked as of its time", () => {
    const grants: Source<PoliciesAnswer> = {
      state: "failed",
      service: "vault",
      lastGood: { data: delegated.policies, readAt: "2026-11-20T14:02:00.000Z" },
    };
    const [row] = rows({ ...delegatedInput, grants });
    expect(row!.mayUse).toEqual({
      state: "ok",
      lines: [
        "mock-database (given by alice@company.com, 20 Nov)",
        "(as of 14:02; could not check now)",
      ],
    });
  });

  it("the revocation service not answering: says it could not check, never 'usable'", () => {
    const [row] = rows({
      ...delegatedInput,
      revocations: { state: "failed", service: "revocation" },
    });
    expect(row!.cutOff).toBe("could not check whether it is cut off");
  });

  it("the identity service not answering: the table names it", () => {
    expect(
      whoView({ ...delegatedInput, agents: { state: "failed", service: "identity" } }).table,
    ).toEqual({
      state: "unreadable",
      tone: "red",
      text: "The identity service is not answering.",
    });
  });

  it("loading: Checking…", () => {
    const view = whoView({
      agents: { state: "loading" },
      grants: { state: "loading" },
      revocations: { state: "loading" },
      ledger: { state: "loading" },
    });
    expect(view.table).toEqual({ state: "loading", text: "Checking…" });
    const [row] = rows({
      ...delegatedInput,
      ledger: { state: "loading" },
      grants: { state: "loading" },
    });
    expect(row!.actingFor).toEqual({ state: "loading", text: "Checking…" });
    expect(row!.mayUse).toEqual({ state: "loading", text: "Checking…" });
  });

  it("no agents: an empty table says so (the first-visit screen is shown instead)", () => {
    const view = whoView({ ...delegatedInput, agents: ok({ agents: [] }) });
    if (view.table.state !== "ok") throw new Error("expected rows");
    expect(view.table.data.empty).toBe("No agents yet.");
  });
});

describe("Who can do what, names and escaping", () => {
  it("an unnamed agent shows as 'unnamed · …' and a short DID; the DID is secondary", () => {
    const agents = ok({ agents: [{ id: "x", did: BILLING, name: null }] });
    const [row] = rows({ ...delegatedInput, agents });
    expect(row!.agent).toBe("unnamed · …a1b2");
    expect(row!.did).toBe(BILLING);
  });

  it("a <script> name is never shown; an agent without a usable DID is skipped", () => {
    const agents = ok({
      agents: [
        { did: BILLING, name: "<script>alert(1)</script>" },
        { did: "not a did", name: "ghost" },
        "junk",
      ],
    });
    expect(rows({ ...delegatedInput, agents }).map((r) => r.agent)).toEqual(["unnamed · …a1b2"]);
  });

  it("a granter or tool name that is not plain text is replaced by words, then escaped", () => {
    const grants = ok({
      grants: [
        {
          agentDid: BILLING,
          tool: "<b>x</b>\n",
          grantedBy: { name: "<i>eve</i>" },
          createdAt: "bad",
        },
        {
          agentDid: BILLING,
          tool: "stripe",
          grantedBy: null,
          createdAt: "2026-11-20T14:01:00.000Z",
        },
        { agentDid: BILLING, tool: "plain" },
        "junk",
      ],
    });
    const [row] = rows({ ...delegatedInput, grants });
    expect(row!.mayUse).toEqual({
      state: "ok",
      lines: ["a tool not shown (given by &lt;i&gt;eve&lt;/i&gt;)", "stripe (20 Nov)", "plain"],
    });
    expect(row!.actingFor).toEqual({
      state: "ok",
      lines: ["&lt;i&gt;eve&lt;/i&gt;", "an operator"],
    });
  });
});

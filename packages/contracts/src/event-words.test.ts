import { describe, expect, it } from "vitest";
import {
  agentLabel,
  chainWords,
  eventSentence,
  plainText,
  principalLabel,
  refusalOfRecord,
  type EventRecord,
} from "./event-words.js";
import { REFUSALS, REFUSAL_REASONS, UNKNOWN_REFUSAL } from "./refusals.js";

const BILLING = "did:web:localhost%3A4001:agents:0000billing-a1b2";
const HELPER = "did:web:localhost%3A4001:agents:0000helper-c3d4";
const ALICE = { kind: "operator", id: "k1", name: "alice@company.com" } as const;
const names: Record<string, string> = { [BILLING]: "billing-bot", [HELPER]: "helper-bot" };
const agent = (did: string) => agentLabel(did, names[did]);

function call(overrides: Partial<EventRecord>): EventRecord {
  return {
    agentDid: BILLING,
    authorityChain: [BILLING],
    tool: "mock-database",
    action: "query",
    policy: { rule: "scoped-token", decision: "allow" },
    ...overrides,
  };
}

function control(action: string, overrides: Partial<EventRecord> = {}): EventRecord {
  return {
    principal: ALICE,
    agentDid: BILLING,
    authorityChain: [],
    action,
    policy: { rule: `control-plane-scope:${action}`, decision: "allow" },
    ...overrides,
  };
}

describe("plainText", () => {
  it("passes printable one-line ASCII within the limit", () => {
    expect(plainText("key leaked")).toBe("key leaked");
    expect(plainText("a".repeat(4), 4)).toBe("aaaa");
  });

  it.each([
    ["too long", "a".repeat(5), 4],
    ["a newline", "a\nb", 128],
    ["an escape", "a\u001b[31m", 128],
    ["a bidi control", `a${String.fromCodePoint(0x202e)}b`, 128],
    ["non-ASCII", "café", 128],
    ["leading space", " a", 128],
    ["empty", "", 128],
    ["not a string", 7, 128],
  ])("refuses %s", (_, value, max) => {
    expect(plainText(value, max)).toBeUndefined();
  });
});

describe("agentLabel", () => {
  it("shows a valid name", () => {
    expect(agentLabel(BILLING, "billing-bot")).toBe("billing-bot");
  });

  it("shows an unnamed agent as 'unnamed · …' and the last four characters", () => {
    expect(agentLabel(BILLING)).toBe("unnamed · …a1b2");
    expect(agentLabel(BILLING, null)).toBe("unnamed · …a1b2");
  });

  it("never shows a name that breaks the naming rule", () => {
    expect(agentLabel(BILLING, "<script>alert(1)</script>")).toBe("unnamed · …a1b2");
  });

  it("does not show a DID that is not plain text", () => {
    expect(agentLabel("did:web:x\nFAKE LINE")).toBe("unnamed · (id not shown)");
  });
});

describe("principalLabel", () => {
  it("names a principal, or says what kind it is", () => {
    expect(principalLabel(ALICE)).toBe("alice@company.com");
    expect(principalLabel({ kind: "service", name: "bad\nname" })).toBe("a service");
    expect(principalLabel({ kind: "operator", name: "bad\nname" })).toBe("an operator");
    expect(principalLabel(undefined)).toBe("someone");
  });
});

describe("refusalOfRecord", () => {
  const deny = (rule: string, reason?: string) =>
    refusalOfRecord(
      call({ policy: { rule, decision: "deny" }, ...(reason === undefined ? {} : { reason }) }),
    );

  it("is undefined for an allowed entry", () => {
    expect(refusalOfRecord(call({}))).toBeUndefined();
  });

  it.each([
    ["agent-tool-allowlist", "POLICY_DENIED"],
    ["revocation", "AGENT_REVOKED"],
    ["revocation-state-unknown", "REVOCATION_STATE_UNKNOWN_AGENT"],
    ["revocation-state-stale", "REVOCATION_STATE_STALE"],
    ["token-scope", "ACTION_MISMATCH"],
    ["unknown-tool", "UNKNOWN_TOOL"],
    ["delegation:mock-database", "DELEGATION_DENIED"],
    ["control-plane-scope:agents:revoke", "UNAUTHORIZED"],
  ])("reads rule %s as %s", (rule, code) => {
    expect(deny(rule)?.code).toBe(code);
  });

  it("only a stale revocation list is an alarm among the vault's recorded rules", () => {
    expect(deny("revocation-state-stale")?.entry.severity).toBe("alarm");
    expect(deny("agent-tool-allowlist")?.entry.severity).toBe("normal");
    expect(deny("revocation")?.entry.severity).toBe("normal");
  });

  it("reads a connector's own code from the reason", () => {
    expect(deny("connector", "UPSTREAM_ERROR")?.code).toBe("UPSTREAM_ERROR");
    expect(deny("connector", "NOT_A_CODE_WE_KNOW")?.code).toBe("UNKNOWN");
    expect(deny("connector", "lower case")?.code).toBe("UNKNOWN");
    expect(deny("connector")?.code).toBe("UNKNOWN");
  });

  it("reads a delegation's finer reason", () => {
    const refusal = deny("delegation:mock-database", "delegation chain refused: EXPIRED");
    expect(refusal?.entry).not.toBe(REFUSALS.DELEGATION_DENIED);
    expect(refusal?.entry.meaning).toBe(REFUSAL_REASONS.DELEGATION_DENIED.EXPIRED.meaning);
    expect(deny("delegation:mock-database", "free text")?.entry).toBe(REFUSALS.DELEGATION_DENIED);
  });

  it("treats an unknown rule as an unknown, normal refusal", () => {
    expect(deny("something-new")).toEqual({ code: "UNKNOWN", entry: UNKNOWN_REFUSAL });
    expect(deny("something-new")?.entry.severity).toBe("normal");
  });
});

describe("eventSentence", () => {
  it("an allowed call", () => {
    expect(eventSentence(call({}), { agent })).toBe(
      "billing-bot used mock-database (query): allowed",
    );
  });

  it("a refused call explains the refusal from the catalogue", () => {
    const record = call({
      tool: "stripe",
      action: "list-customers",
      policy: { rule: "agent-tool-allowlist", decision: "deny" },
    });
    expect(eventSentence(record, { agent })).toBe(
      `billing-bot asked to use stripe (list-customers): refused. ${REFUSALS.POLICY_DENIED.meaning}`,
    );
  });

  it("a cut-off, with its reason", () => {
    expect(eventSentence(control("agents.revoke", { reason: "key leaked" }), { agent })).toBe(
      "alice@company.com cut off billing-bot: key leaked",
    );
    expect(eventSentence(control("agents.revoke"), { agent })).toBe(
      "alice@company.com cut off billing-bot",
    );
  });

  it("drops a reason that is not plain text rather than printing it", () => {
    expect(eventSentence(control("agents.revoke", { reason: "a\nFAKE" }), { agent })).toBe(
      "alice@company.com cut off billing-bot",
    );
  });

  it("a refused cut-off", () => {
    const record = control("agents.revoke", {
      policy: { rule: "control-plane-scope:agents:revoke", decision: "deny" },
    });
    expect(eventSentence(record, { agent })).toBe(
      `alice@company.com tried to cut off billing-bot: refused. ${REFUSALS.UNAUTHORIZED.meaning}`,
    );
  });

  it.each([
    ["agents.register", {}, "alice@company.com registered billing-bot"],
    [
      "policies.grant",
      { tool: "mock-database" },
      "alice@company.com gave billing-bot mock-database",
    ],
    ["policies.grant", {}, "alice@company.com gave billing-bot a tool"],
    [
      "credentials.store",
      { tool: "stripe", agentDid: undefined },
      "alice@company.com stored the credential for stripe",
    ],
    [
      "status.allocate",
      {},
      "alice@company.com reserved billing-bot's place on the revocation list",
    ],
    ["operator.login", { agentDid: undefined }, "alice@company.com signed in"],
    ["something.else", {}, "alice@company.com did something.else on billing-bot: allowed"],
    ["something.else", { agentDid: undefined }, "alice@company.com did something.else: allowed"],
  ])("control-plane %s", (action, overrides, sentence) => {
    expect(eventSentence(control(action, overrides as Partial<EventRecord>), { agent })).toBe(
      sentence,
    );
  });

  it.each([
    ["agents.register", "alice@company.com tried to register an agent: refused."],
    ["policies.grant", "alice@company.com tried to give billing-bot a tool: refused."],
    ["credentials.store", "alice@company.com tried to store the credential for a tool: refused."],
    [
      "status.allocate",
      "alice@company.com tried to reserve a place on the revocation list: refused.",
    ],
    ["operator.login", "alice@company.com tried to sign in: refused."],
    ["something.else", "alice@company.com did something.else on billing-bot: refused."],
  ])("refused control-plane %s", (action, start) => {
    const record = control(action, {
      policy: { rule: `control-plane-scope:${action}`, decision: "deny" },
    });
    expect(eventSentence(record, { agent }).startsWith(start)).toBe(true);
  });

  it("without names, agents show unnamed", () => {
    expect(eventSentence(call({}))).toBe("unnamed · …a1b2 used mock-database (query): allowed");
  });

  it("a tool or action that is not plain text is replaced by words", () => {
    expect(eventSentence(call({ tool: "<b>\n", action: "q\u0000" }), { agent })).toBe(
      "billing-bot used a tool (an action): allowed",
    );
    expect(eventSentence(call({ tool: undefined }), { agent })).toBe(
      "billing-bot used query: allowed",
    );
  });

  it("an entry naming no agent or principal still reads", () => {
    expect(eventSentence(call({ agentDid: undefined }))).toBe(
      "an agent used mock-database (query): allowed",
    );
    expect(eventSentence(control("agents.revoke", { agentDid: undefined }))).toBe(
      "alice@company.com cut off an agent",
    );
  });

  it("a delegated issuance names the chain from its evidence's root", () => {
    const record = call({
      agentDid: HELPER,
      authorityChain: [BILLING, HELPER],
      delegationRef: "ref",
      delegation: { root: ALICE },
      policy: { rule: "delegation:mock-database", decision: "allow" },
    });
    expect(eventSentence(record, { agent })).toBe(
      "helper-bot was given a pass for mock-database (query) for alice@company.com → billing-bot → helper-bot: allowed",
    );
  });

  it("a delegated call uses the root the caller linked, or says it is not linked", () => {
    const record = call({
      agentDid: HELPER,
      authorityChain: [BILLING, HELPER],
      delegationRef: "ref",
    });
    expect(eventSentence(record, { agent, chainRoot: "alice@company.com" })).toBe(
      "helper-bot used mock-database (query) for alice@company.com → billing-bot → helper-bot: allowed",
    );
    expect(chainWords(record, { agent })).toBe("(not linked) → billing-bot → helper-bot");
    expect(chainWords(record)).toBe("(not linked) → unnamed · …a1b2 → unnamed · …c3d4");
  });

  it("an undelegated entry has no chain", () => {
    expect(chainWords(call({}))).toBeUndefined();
  });
});

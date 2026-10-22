import { describe, expect, it } from "vitest";
import { codeFromReason, cutOffMessage, foreignViewOf, recordedSince } from "./foreign.js";

const AT = "2026-10-22T12:00:00.000Z";

function record(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    agentDid: "did:web:localhost%3A4001:agents:a1",
    tool: "b-ledger",
    action: "read",
    policy: { rule: "foreign:org-a.test", decision: "deny" },
    reason: "issuer=did:web:localhost%3A4001 code=AGENT_REVOKED",
    recordedAt: AT,
    ...overrides,
  };
}

describe("foreignViewOf", () => {
  it("reads the organisation, the agent, the decision and the denial code", () => {
    expect(foreignViewOf(record())).toEqual({
      organisation: "org-a.test",
      agentDid: "did:web:localhost%3A4001:agents:a1",
      decision: "deny",
      code: "AGENT_REVOKED",
      tool: "b-ledger",
      recordedAt: AT,
    });
  });

  it("has no code for an allow, whatever the reason says", () => {
    const view = foreignViewOf(
      record({ policy: { rule: "foreign:org-a.test", decision: "allow" } }),
    );
    expect(view?.decision).toBe("allow");
    expect(view?.code).toBeUndefined();
  });

  it("ignores this organisation's own decisions", () => {
    for (const rule of [
      "agent-tool-allowlist",
      "revocation",
      "control-plane-scope:x",
      "foreignx",
    ]) {
      expect(foreignViewOf(record({ policy: { rule, decision: "deny" } }))).toBeUndefined();
    }
  });

  it.each([
    ["not an object", "x"],
    ["null", null],
    ["an array", []],
    ["no policy", record({ policy: undefined })],
    ["a policy that is not an object", record({ policy: "foreign:a" })],
    ["a rule that is not a string", record({ policy: { rule: 7, decision: "deny" } })],
    ["an empty organisation", record({ policy: { rule: "foreign:", decision: "deny" } })],
    ["an unknown decision", record({ policy: { rule: "foreign:a", decision: "maybe" } })],
    ["no agent", record({ agentDid: undefined })],
    ["an empty agent", record({ agentDid: "" })],
    ["no time", record({ recordedAt: undefined })],
    ["an unreadable time", record({ recordedAt: "yesterday" })],
  ])("skips %s, without throwing", (_label, claims) => {
    expect(foreignViewOf(claims)).toBeUndefined();
  });

  it("keeps a record with no tool", () => {
    expect(foreignViewOf(record({ tool: undefined }))?.tool).toBeUndefined();
  });
});

describe("codeFromReason", () => {
  it.each([
    ["issuer=did:web:a code=AGENT_REVOKED", "AGENT_REVOKED"],
    ["issuer=did:web:a code=STATUS_ENTRY_INVALID missing", "STATUS_ENTRY_INVALID"],
    ["code=STATUS_STALE", "STATUS_STALE"],
  ])("reads %s", (reason, code) => {
    expect(codeFromReason(reason)).toBe(code);
  });

  it.each([undefined, 7, "", "no code here", "xcode=AGENT_REVOKED", "code=lowercase"])(
    "finds nothing in %s",
    (reason) => {
      expect(codeFromReason(reason)).toBeUndefined();
    },
  );
});

describe("recordedSince", () => {
  it("keeps what happened at or after the page opened, and drops what came before", () => {
    const view = foreignViewOf(record());
    if (view === undefined) throw new Error("fixture");
    const at = Date.parse(AT);
    expect(recordedSince(view, at)).toBe(true);
    expect(recordedSince(view, at - 1)).toBe(true);
    expect(recordedSince(view, at + 1)).toBe(false);
  });
});

describe("cutOffMessage", () => {
  it("announces an agent revoked by its own organisation", () => {
    const view = foreignViewOf(record());
    if (view === undefined) throw new Error("fixture");
    expect(cutOffMessage(view, "a1")).toBe(
      "🔌 a1 from org-a.test refused: revoked by its own organisation",
    );
  });

  it("stays quiet for an allow or any other refusal", () => {
    const allowed = foreignViewOf(record({ policy: { rule: "foreign:a", decision: "allow" } }));
    const stale = foreignViewOf(record({ reason: "issuer=x code=STATUS_STALE" }));
    if (allowed === undefined || stale === undefined) throw new Error("fixture");
    expect(cutOffMessage(allowed, "a1")).toBeUndefined();
    expect(cutOffMessage(stale, "a1")).toBeUndefined();
  });
});

import { describe, expect, it } from "vitest";
import { isAuditRecord, type AuditRecord } from "./record.js";

const AGENT_DID = "did:web:localhost%3A4001:agents:0f8f6a1e-9c2b-4a3d-8f1e-1b2c3d4e5f60";

function recordFor(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    agentDid: AGENT_DID,
    authorityChain: [AGENT_DID],
    tool: "github",
    action: "list-repos",
    dataCategories: ["repository-metadata"],
    policy: { rule: "agent-tool-allowlist", decision: "allow" },
    recordedAt: "2026-09-12T10:00:00.000Z",
    ...overrides,
  };
}

describe("isAuditRecord", () => {
  it("accepts an agent action", () => {
    expect(isAuditRecord(recordFor())).toBe(true);
  });

  it("accepts a control-plane record: a principal, no agent, an empty authority chain", () => {
    expect(
      isAuditRecord({
        principal: { kind: "operator", id: "0123456789abcdef", name: "lakshya" },
        authorityChain: [],
        tool: "stripe",
        action: "credentials.store",
        dataCategories: [],
        policy: { rule: "control-plane-scope:credentials:write", decision: "allow" },
        recordedAt: "2026-10-02T10:00:00.000Z",
      }),
    ).toBe(true);
  });

  it("accepts a reason and the reporting service (ADR 0017 §4)", () => {
    expect(
      isAuditRecord(
        recordFor({
          reason: "code=AGENT_REVOKED",
          reportedBy: { kind: "service", id: "0123456789abcdef", name: "vault" },
        }),
      ),
    ).toBe(true);
  });

  it.each([
    ["no actor: neither agentDid nor principal", { ...recordFor(), agentDid: undefined }],
    ["empty agentDid", { ...recordFor(), agentDid: "" }],
    ["missing authorityChain", { ...recordFor(), authorityChain: undefined }],
    ["non-array authorityChain", { ...recordFor(), authorityChain: AGENT_DID }],
    ["non-string authorityChain entry", { ...recordFor(), authorityChain: [1] }],
    ["empty tool", { ...recordFor(), tool: "" }],
    ["missing action", { ...recordFor(), action: undefined }],
    ["empty action", { ...recordFor(), action: "" }],
    ["missing dataCategories", { ...recordFor(), dataCategories: undefined }],
    ["non-array dataCategories", { ...recordFor(), dataCategories: "repository-metadata" }],
    ["missing recordedAt", { ...recordFor(), recordedAt: undefined }],
    ["non-string reason", { ...recordFor(), reason: 7 }],
    ["missing policy", { ...recordFor(), policy: undefined }],
    ["non-object policy", { ...recordFor(), policy: "allow" }],
    ["missing policy.rule", { ...recordFor(), policy: { decision: "allow" } }],
    ["invalid policy.decision", { ...recordFor(), policy: { rule: "x", decision: "maybe" } }],
    ["non-object principal", { ...recordFor(), principal: "lakshya" }],
    [
      "unknown principal kind",
      { ...recordFor(), principal: { kind: "agent", id: "a", name: "b" } },
    ],
    ["principal without id", { ...recordFor(), principal: { kind: "operator", name: "b" } }],
    [
      "principal with empty name",
      { ...recordFor(), principal: { kind: "operator", id: "a", name: "" } },
    ],
    ["non-object reporter", { ...recordFor(), reportedBy: "vault" }],
    [
      "reporter with empty id",
      { ...recordFor(), reportedBy: { kind: "service", id: "", name: "v" } },
    ],
    ["null", null],
    ["an array", []],
    ["a string", "audited"],
  ])("rejects %s", (_label, value) => {
    expect(isAuditRecord(value)).toBe(false);
  });
});

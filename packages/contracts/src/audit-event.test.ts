import { describe, expect, it } from "vitest";
import { auditEventSchema } from "./audit-event.js";

const agentEvent = {
  agentDid: "did:web:localhost%3A4001:agents:a1",
  tool: "mock-slack",
  action: "post-message",
  dataCategories: ["messaging-content"],
  policy: { rule: "agent-tool-allowlist", decision: "allow" },
};

const controlPlaneEvent = {
  principal: { kind: "operator", id: "0123456789abcdef", name: "lakshya" },
  tool: "stripe",
  action: "credentials.store",
  dataCategories: [],
  policy: { rule: "control-plane-scope:credentials:write", decision: "allow" },
};

const ROOT = "did:web:localhost%3A4001:agents:root";
const delegatedEvent = {
  ...agentEvent,
  policy: { rule: "delegation:mock-slack", decision: "allow" },
  authorityChain: [ROOT, agentEvent.agentDid],
  delegationRef: "A".repeat(43),
};
const evidence = {
  root: { kind: "operator", id: "0123456789abcdef", name: "lakshya", via: "custos-admin" },
  handOffs: ["a.b"],
  credentials: [{ id: "c" }],
  checkedAt: "2026-11-09T10:00:00.000Z",
};

describe("auditEventSchema", () => {
  it("accepts an agent action and a control-plane action", () => {
    expect(auditEventSchema.safeParse(agentEvent).success).toBe(true);
    expect(auditEventSchema.safeParse(controlPlaneEvent).success).toBe(true);
  });

  it("accepts a control-plane action about an agent, with no tool", () => {
    const event = { ...controlPlaneEvent, tool: undefined, agentDid: agentEvent.agentDid };
    expect(auditEventSchema.safeParse(event).success).toBe(true);
  });

  it("accepts a delegated call and a delegated issuance with its evidence (ADR 0020 §6)", () => {
    expect(auditEventSchema.safeParse(delegatedEvent).success).toBe(true);
    const issued = auditEventSchema.safeParse({ ...delegatedEvent, delegation: evidence });
    expect(issued.success).toBe(true);
    // The credentials pass through as presented, field for field.
    if (issued.success) expect(issued.data.delegation?.credentials).toEqual(evidence.credentials);
  });

  it("admits the largest chain a vault can be configured to accept", () => {
    const big = {
      ...evidence,
      handOffs: ["h".repeat(200_000)],
      credentials: [{ x: "c".repeat(62_000) }],
    };
    expect(auditEventSchema.safeParse({ ...delegatedEvent, delegation: big }).success).toBe(true);
  });

  it.each([
    ["a chain of one", { ...delegatedEvent, authorityChain: [agentEvent.agentDid] }],
    [
      "a chain not ending at the agent",
      { ...delegatedEvent, authorityChain: [agentEvent.agentDid, ROOT] },
    ],
    [
      "a chain on a control-plane action",
      { ...delegatedEvent, principal: controlPlaneEvent.principal },
    ],
    [
      "a chain of 17",
      { ...delegatedEvent, authorityChain: [...Array(16).fill(ROOT), agentEvent.agentDid] },
    ],
    ["a chain with no reference", { ...delegatedEvent, delegationRef: undefined }],
    ["a reference with no chain", { ...agentEvent, delegationRef: "r" }],
    ["an oversized reference", { ...delegatedEvent, delegationRef: "r".repeat(65) }],
    ["evidence with no chain", { ...agentEvent, delegation: evidence }],
    [
      "evidence with no hand-offs",
      { ...delegatedEvent, delegation: { ...evidence, handOffs: [] } },
    ],
    [
      "evidence with 17 credentials",
      { ...delegatedEvent, delegation: { ...evidence, credentials: Array(17).fill({}) } },
    ],
    [
      "evidence rooted at an unknown via",
      { ...delegatedEvent, delegation: { ...evidence, root: { ...evidence.root, via: "x" } } },
    ],
    [
      "evidence with a bad checkedAt",
      { ...delegatedEvent, delegation: { ...evidence, checkedAt: "yesterday" } },
    ],
    [
      "evidence over the size bound",
      {
        ...delegatedEvent,
        delegation: {
          ...evidence,
          handOffs: ["h".repeat(200_000)],
          credentials: [{ x: "c".repeat(70_000) }],
        },
      },
    ],
  ])("rejects %s", (_label, event) => {
    expect(auditEventSchema.safeParse(event).success).toBe(false);
  });

  it.each([
    ["no actor", { ...controlPlaneEvent, principal: undefined }],
    [
      "unknown principal kind",
      { ...controlPlaneEvent, principal: { kind: "agent", id: "a", name: "b" } },
    ],
    [
      "empty principal name",
      { ...controlPlaneEvent, principal: { kind: "operator", id: "a", name: "" } },
    ],
    ["oversized agentDid", { ...agentEvent, agentDid: "d".repeat(513) }],
    ["oversized reason", { ...agentEvent, reason: "r".repeat(1025) }],
    ["too many data categories", { ...agentEvent, dataCategories: Array(65).fill("x") }],
    ["invalid decision", { ...agentEvent, policy: { rule: "x", decision: "maybe" } }],
    ["empty action", { ...agentEvent, action: "" }],
  ])("rejects %s", (_label, event) => {
    expect(auditEventSchema.safeParse(event).success).toBe(false);
  });
});

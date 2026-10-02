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

describe("auditEventSchema", () => {
  it("accepts an agent action and a control-plane action", () => {
    expect(auditEventSchema.safeParse(agentEvent).success).toBe(true);
    expect(auditEventSchema.safeParse(controlPlaneEvent).success).toBe(true);
  });

  it("accepts a control-plane action about an agent, with no tool", () => {
    const event = { ...controlPlaneEvent, tool: undefined, agentDid: agentEvent.agentDid };
    expect(auditEventSchema.safeParse(event).success).toBe(true);
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

import { auditEventSchema } from "@custos/contracts";
import { describe, expect, it } from "vitest";
import { controlPlaneEvent } from "./control-plane.js";

const principal = { kind: "operator" as const, id: "0123456789abcdef", name: "lakshya" };

describe("controlPlaneEvent", () => {
  it("builds a valid event naming the principal, scope and target", () => {
    const event = controlPlaneEvent({
      principal,
      scope: "agents:revoke",
      action: "agents.revoke",
      decision: "allow",
      agentDid: "did:web:x:agents:1",
      reason: "compromised",
    });
    expect(event).toEqual({
      principal,
      action: "agents.revoke",
      dataCategories: [],
      policy: { rule: "control-plane-scope:agents:revoke", decision: "allow" },
      agentDid: "did:web:x:agents:1",
      reason: "compromised",
    });
    expect(auditEventSchema.safeParse(event).success).toBe(true);
  });

  it("records only kind, id and name, never the principal's scopes", () => {
    const event = controlPlaneEvent({
      principal: { ...principal, scopes: new Set(["credentials:write"]) } as typeof principal,
      scope: "credentials:write",
      action: "credentials.store",
      decision: "deny",
      tool: "stripe",
    });
    expect(event.principal).toEqual(principal);
    expect(auditEventSchema.safeParse(event).success).toBe(true);
  });
});

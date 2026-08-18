import { describe, expect, it } from "vitest";
import type { Connector } from "./connector.js";

describe("Connector", () => {
  it("can be implemented by a concrete adapter", async () => {
    const revoked: string[] = [];
    const fake: Connector = {
      tool: "github",
      revoke: async (agentId) => {
        revoked.push(agentId);
      },
    };

    await fake.revoke("agent-1");

    expect(fake.tool).toBe("github");
    expect(revoked).toEqual(["agent-1"]);
  });
});

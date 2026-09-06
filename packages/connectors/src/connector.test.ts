import { describe, expect, it } from "vitest";
import { ok } from "@custos/contracts";
import type { Connector } from "./connector.js";

describe("Connector", () => {
  it("can be implemented by a concrete adapter", async () => {
    const revoked: string[] = [];
    const fake: Connector = {
      tool: "github",
      call: async ({ action }) => ok({ action }),
      revoke: async (agentId) => {
        revoked.push(agentId);
      },
    };

    await fake.revoke("agent-1");
    const result = await fake.call({ action: "noop", input: {}, credential: "secret" });

    expect(fake.tool).toBe("github");
    expect(revoked).toEqual(["agent-1"]);
    expect(result).toEqual({ ok: true, value: { action: "noop" } });
  });
});

import { describe, expect, it } from "vitest";
import { ok } from "@custos/contracts";
import type { Connector } from "./connector.js";

const AGENT_DID = "did:web:127.0.0.1%3A4001:agents:11111111-1111-4111-8111-111111111111";

describe("Connector", () => {
  it("can be implemented by a concrete adapter", async () => {
    const revoked: string[] = [];
    const fake: Connector = {
      tool: "github",
      dataCategories: ["repository-metadata"],
      call: async ({ action }) => ok({ action }),
      revoke: async (agentId) => {
        revoked.push(agentId);
      },
    };

    await fake.revoke("agent-1");
    const result = await fake.call({
      action: "noop",
      input: {},
      credential: "secret",
      agentId: AGENT_DID,
    });

    expect(fake.tool).toBe("github");
    expect(revoked).toEqual(["agent-1"]);
    expect(result).toEqual({ ok: true, value: { action: "noop" } });
  });
});

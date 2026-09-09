import { describe, expect, it } from "vitest";
import { createMockSlackConnector } from "./mock-slack.js";

const AGENT_DID = "did:web:127.0.0.1%3A4001:agents:11111111-1111-4111-8111-111111111111";

describe("createMockSlackConnector", () => {
  it("posts a message and records it", async () => {
    const connector = createMockSlackConnector();

    const result = await connector.call({
      action: "post-message",
      input: { channel: "#general", text: "hello" },
      credential: "xoxb-fake",
      agentId: AGENT_DID,
    });

    expect(result.ok).toBe(true);
    expect(connector.messages).toEqual([{ id: "msg_1", channel: "#general", text: "hello" }]);
  });

  it("rejects an unknown action", async () => {
    const connector = createMockSlackConnector();
    const result = await connector.call({
      action: "delete-channel",
      input: {},
      credential: "x",
      agentId: AGENT_DID,
    });
    expect(result).toEqual({
      ok: false,
      error: { code: "UNKNOWN_ACTION", action: "delete-channel" },
    });
  });

  it("rejects malformed input", async () => {
    const connector = createMockSlackConnector();
    const result = await connector.call({
      action: "post-message",
      input: { channel: "#general" },
      credential: "x",
      agentId: AGENT_DID,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("INVALID_INPUT");
  });

  it("revoke() is a no-op — the fake tool has no real access to revoke", async () => {
    const connector = createMockSlackConnector();
    await expect(connector.revoke("agent-1")).resolves.toBeUndefined();
  });
});

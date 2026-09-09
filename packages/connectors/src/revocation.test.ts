import { describe, expect, it } from "vitest";
import { createMockDatabaseConnector } from "./mock-database.js";
import { createMockSlackConnector } from "./mock-slack.js";
import { createStripeConnector } from "./stripe.js";
import { createRevocationGuard, type Connector } from "./connector.js";

const AGENT = "did:web:127.0.0.1%3A4001:agents:11111111-1111-4111-8111-111111111111";
const OTHER_AGENT = "did:web:127.0.0.1%3A4001:agents:22222222-2222-4222-8222-222222222222";

/** One working call per connector, so the revoked case is a real contrast. */
const CONNECTORS: readonly {
  readonly name: string;
  readonly make: () => Connector;
  readonly action: string;
  readonly input: unknown;
}[] = [
  {
    name: "mock-slack",
    make: () => createMockSlackConnector(),
    action: "post-message",
    input: { channel: "#ops", text: "hello" },
  },
  {
    name: "mock-database",
    make: () => createMockDatabaseConnector(),
    action: "query",
    input: { table: "customers" },
  },
  {
    name: "stripe",
    // Never reaches the network: the revocation guard refuses first.
    make: () => createStripeConnector({ baseUrl: "http://127.0.0.1:1/" }),
    action: "list-customers",
    input: undefined,
  },
];

describe("connectors honour revocation", () => {
  it.each(CONNECTORS)("$name refuses a revoked agent", async ({ make, action, input }) => {
    const connector = make();
    await connector.revoke(AGENT);

    const result = await connector.call({ action, input, credential: "secret", agentId: AGENT });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("AGENT_REVOKED");
      if (result.error.code === "AGENT_REVOKED") expect(result.error.agentId).toBe(AGENT);
    }
  });

  it.each(CONNECTORS)(
    "$name still serves other agents after one is revoked",
    async ({ make, action, input }) => {
      const connector = make();
      await connector.revoke(AGENT);

      const result = await connector.call({
        action,
        input,
        credential: "secret",
        agentId: OTHER_AGENT,
      });

      // Only the revoked agent is cut off — revoking one must not take down
      // every other agent sharing the same tool credential.
      if (!result.ok) expect(result.error.code).not.toBe("AGENT_REVOKED");
    },
  );

  it.each(CONNECTORS)("$name refuses a revoked agent before validating input", async ({ make }) => {
    const connector = make();
    await connector.revoke(AGENT);

    const result = await connector.call({
      action: "definitely-not-a-real-action",
      input: { nonsense: true },
      credential: "secret",
      agentId: AGENT,
    });

    // Revocation outranks every other rejection reason: a revoked agent
    // should never learn whether its action or input would have been valid.
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("AGENT_REVOKED");
  });

  it.each(CONNECTORS)("$name revocation is idempotent", async ({ make, action, input }) => {
    const connector = make();
    await connector.revoke(AGENT);
    await expect(connector.revoke(AGENT)).resolves.toBeUndefined();

    const result = await connector.call({ action, input, credential: "secret", agentId: AGENT });
    expect(result.ok).toBe(false);
  });

  it.each(CONNECTORS)(
    "$name permits the agent until it is revoked",
    async ({ make, action, input }) => {
      const connector = make();

      const result = await connector.call({ action, input, credential: "secret", agentId: AGENT });

      if (!result.ok) expect(result.error.code).not.toBe("AGENT_REVOKED");
    },
  );
});

describe("createRevocationGuard", () => {
  it("reports an agent as revoked only after revoke is called", () => {
    const guard = createRevocationGuard();
    expect(guard.isRevoked(AGENT)).toBe(false);
    guard.revoke(AGENT);
    expect(guard.isRevoked(AGENT)).toBe(true);
  });

  it("tracks agents independently", () => {
    const guard = createRevocationGuard();
    guard.revoke(AGENT);
    expect(guard.isRevoked(OTHER_AGENT)).toBe(false);
  });
});

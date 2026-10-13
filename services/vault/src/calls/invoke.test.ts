import { randomUUID } from "node:crypto";
import {
  createLocalSecretCipher,
  generateKeyPair,
  issueScopedToken,
  sign,
  type ScopedTokenClaims,
} from "@custos/core";
import { err, ok } from "@custos/contracts";
import type { Connector } from "@custos/connectors";
import { afterAll, describe, expect, it } from "vitest";
import { storeToolCredential } from "../credentials/store.js";
import { createDb } from "../db/client.js";
import { invokeTool } from "./invoke.js";

/** Nobody revoked, state fresh — the baseline these tests assume. */
const neverRevoked = { verdict: () => "ok" as const, isStale: () => false };

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);
const cipher = createLocalSecretCipher(new Uint8Array(32).fill(5));

afterAll(async () => {
  await db.$client.end();
});

function recordingConnector(tool: string): Connector & { readonly calls: readonly unknown[] } {
  const calls: unknown[] = [];
  return {
    tool,
    dataCategories: ["test-data"],
    get calls() {
      return calls;
    },
    async call({ action, input, credential }) {
      calls.push({ action, input, credential });
      if (action === "reject-me") return err({ code: "UNKNOWN_ACTION", action });
      return ok({ echoedCredential: credential });
    },
    async revoke() {
      // not exercised in these tests
    },
  };
}

async function mintToken(
  claims: Omit<ScopedTokenClaims, "iat" | "exp"> & { iat: number; exp: number },
) {
  const { publicKey, secretKey } = generateKeyPair();
  const issued = await issueScopedToken({
    claims,
    signer: { sign: (data) => Promise.resolve(sign(data, secretKey)) },
  });
  if (!issued.ok) throw new Error("expected token issuance to succeed");
  return { token: issued.value, publicKey };
}

describe("invokeTool", () => {
  it("verifies the token, decrypts the credential, and calls the connector", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db, cipher, tool, secret: "sk_test_x" });
    const connector = recordingConnector(tool);
    const now = new Date("2026-01-01T00:00:00Z");
    const { token, publicKey } = await mintToken({
      sub: "did:web:localhost:agents:a1",
      tool,
      action: "list-customers",
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 60,
    });

    const result = await invokeTool({
      db,
      cipher,
      connectors: new Map([[tool, connector]]),
      token,
      vaultPublicKey: publicKey,
      action: "list-customers",
      input: { limit: 5 },
      now,
      revocation: neverRevoked,
    });

    expect(result).toEqual({ ok: true, value: { echoedCredential: "sk_test_x" } });
    expect(connector.calls).toEqual([
      { action: "list-customers", input: { limit: 5 }, credential: "sk_test_x" },
    ]);
  });

  it("rejects a token signed by an unrelated key", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db, cipher, tool, secret: "sk_test_x" });
    const now = new Date();
    const { token } = await mintToken({
      sub: "did:web:localhost:agents:a1",
      tool,
      action: "list-customers",
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 60,
    });
    const { publicKey: unrelatedPublicKey } = generateKeyPair();

    const result = await invokeTool({
      db,
      cipher,
      connectors: new Map([[tool, recordingConnector(tool)]]),
      token,
      vaultPublicKey: unrelatedPublicKey,
      action: "list-customers",
      input: {},
      now,
      revocation: neverRevoked,
    });

    expect(result).toEqual({
      ok: false,
      error: { code: "INVALID_TOKEN", reason: "SIGNATURE_INVALID" },
    });
  });

  it("rejects an expired token", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db, cipher, tool, secret: "sk_test_x" });
    const issuedAt = new Date("2026-01-01T00:00:00Z");
    const { token, publicKey } = await mintToken({
      sub: "did:web:localhost:agents:a1",
      tool,
      action: "list-customers",
      iat: Math.floor(issuedAt.getTime() / 1000),
      exp: Math.floor(issuedAt.getTime() / 1000) + 60,
    });

    const result = await invokeTool({
      db,
      cipher,
      connectors: new Map([[tool, recordingConnector(tool)]]),
      token,
      vaultPublicKey: publicKey,
      action: "list-customers",
      input: {},
      now: new Date(issuedAt.getTime() + 61_000),
      revocation: neverRevoked,
    });

    expect(result).toEqual({ ok: false, error: { code: "INVALID_TOKEN", reason: "EXPIRED" } });
  });

  it("rejects a call for an action outside the token's scope", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db, cipher, tool, secret: "sk_test_x" });
    const now = new Date();
    const { token, publicKey } = await mintToken({
      sub: "did:web:localhost:agents:a1",
      tool,
      action: "list-customers",
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 60,
    });

    const result = await invokeTool({
      db,
      cipher,
      connectors: new Map([[tool, recordingConnector(tool)]]),
      token,
      vaultPublicKey: publicKey,
      action: "delete-everything",
      input: {},
      now,
      revocation: neverRevoked,
    });

    expect(result).toEqual({ ok: false, error: { code: "ACTION_MISMATCH" } });
  });

  describe("the revocation verdict", () => {
    async function callWith(verdict: "ok" | "revoked" | "unknown") {
      const tool = `test-tool-${randomUUID()}`;
      await storeToolCredential({ db, cipher, tool, secret: "sk_test_x" });
      const now = new Date();
      const agent = "did:web:localhost:agents:a1";
      const { token, publicKey } = await mintToken({
        sub: agent,
        tool,
        action: "list-customers",
        iat: Math.floor(now.getTime() / 1000),
        exp: Math.floor(now.getTime() / 1000) + 60,
      });
      const events: unknown[] = [];
      const connector = recordingConnector(tool);
      const result = await invokeTool({
        db,
        cipher,
        connectors: new Map([[tool, connector]]),
        token,
        vaultPublicKey: publicKey,
        action: "list-customers",
        input: {},
        now,
        revocation: { verdict: () => verdict, isStale: () => false },
        auditReporter: { report: (event) => void events.push(event) },
      });
      return { result, events, agent, connector };
    }

    it("denies a revoked agent and records that it was revoked", async () => {
      const { result, events, agent } = await callWith("revoked");

      expect(result).toEqual({ ok: false, error: { code: "AGENT_REVOKED", agentId: agent } });
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        policy: { rule: "revocation", decision: "deny" },
        reason: "agent is revoked",
      });
    });

    // Not the same as revoked, and the evidence log must not say it was.
    it("denies an agent the view cannot place, and records that reason instead", async () => {
      const { result, events, agent, connector } = await callWith("unknown");

      expect(result).toEqual({
        ok: false,
        error: { code: "REVOCATION_STATE_UNKNOWN_AGENT", agentId: agent },
      });
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        policy: { rule: "revocation-state-unknown", decision: "deny" },
        reason: "no status list index is known for this agent",
      });
      expect(JSON.stringify(events[0])).not.toContain("is revoked");
      expect(connector.calls).toHaveLength(0);
    });
  });

  it("rejects a token scoped to a tool with a registered connector but no stored credential", async () => {
    const tool = `test-tool-${randomUUID()}`;
    const now = new Date();
    const { token, publicKey } = await mintToken({
      sub: "did:web:localhost:agents:a1",
      tool,
      action: "list-customers",
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 60,
    });

    const result = await invokeTool({
      db,
      cipher,
      connectors: new Map([[tool, recordingConnector(tool)]]),
      token,
      vaultPublicKey: publicKey,
      action: "list-customers",
      input: {},
      now,
      revocation: neverRevoked,
    });

    expect(result).toEqual({ ok: false, error: { code: "UNKNOWN_TOOL", tool } });
  });

  it("rejects a token scoped to a tool with no registered connector", async () => {
    const tool = `test-tool-${randomUUID()}`;
    const now = new Date();
    const { token, publicKey } = await mintToken({
      sub: "did:web:localhost:agents:a1",
      tool,
      action: "list-customers",
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 60,
    });

    const result = await invokeTool({
      db,
      cipher,
      connectors: new Map(),
      token,
      vaultPublicKey: publicKey,
      action: "list-customers",
      input: {},
      now,
      revocation: neverRevoked,
    });

    expect(result).toEqual({ ok: false, error: { code: "UNKNOWN_TOOL", tool } });
  });

  it("propagates a connector-level error", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db, cipher, tool, secret: "sk_test_x" });
    const now = new Date();
    const { token, publicKey } = await mintToken({
      sub: "did:web:localhost:agents:a1",
      tool,
      action: "reject-me",
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 60,
    });

    const result = await invokeTool({
      db,
      cipher,
      connectors: new Map([[tool, recordingConnector(tool)]]),
      token,
      vaultPublicKey: publicKey,
      action: "reject-me",
      input: {},
      now,
      revocation: neverRevoked,
    });

    expect(result).toEqual({ ok: false, error: { code: "UNKNOWN_ACTION", action: "reject-me" } });
  });
});

import type { SignedCredential } from "@custos/core";
import { createLocalSecretCipher } from "@custos/core";
import {
  createMockDatabaseConnector,
  createMockSlackConnector,
  type Connector,
} from "@custos/connectors";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import { mutableClock } from "@custos/testing";
import type { FastifyInstance } from "fastify";
import { afterAll, describe, expect, it } from "vitest";
import { createDb } from "./db/client.js";
import { buildServer } from "./server.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const vaultDb = createDb(databaseUrl);
const identityDb = createIdentityDb(databaseUrl);
const cipher = createLocalSecretCipher(new Uint8Array(32).fill(11));

afterAll(async () => {
  await vaultDb.$client.end();
  await identityDb.$client.end();
});

async function withRegisteredAgent<T>(
  port: number,
  run: (credential: SignedCredential) => Promise<T>,
): Promise<T> {
  const app: FastifyInstance = buildIdentityServer({
    db: identityDb,
    didDomain: `localhost:${port}`,
  });
  await app.listen({ port, host: "127.0.0.1" });
  try {
    const response = await fetch(`http://localhost:${port}/agents`, { method: "POST" });
    const { credential } = (await response.json()) as { credential: SignedCredential };
    return await run(credential);
  } finally {
    await app.close();
  }
}

describe("vault service", () => {
  it("responds to /health", async () => {
    const app = await buildServer({ db: vaultDb, cipher });
    const response = await app.inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "vault" });
  });

  it("runs the full Phase 2 lifecycle: request a token, call the tool, watch the token expire, request a fresh one", async () => {
    await withRegisteredAgent(4501, async (credential) => {
      const slack = createMockSlackConnector();
      const clock = mutableClock("2026-01-01T00:00:00Z");
      const app = await buildServer({
        db: vaultDb,
        cipher,
        connectors: [slack as Connector],
        clock,
      });

      const seed = await app.inject({
        method: "POST",
        url: "/credentials",
        payload: { tool: "mock-slack", secret: "xoxb-fake-bot-token" },
      });
      expect(seed.statusCode).toBe(201);

      const tokenResponse = await app.inject({
        method: "POST",
        url: "/tokens",
        payload: { tool: "mock-slack", action: "post-message", credential },
      });
      expect(tokenResponse.statusCode).toBe(200);
      const { token, expiresAt } = tokenResponse.json();
      expect(expiresAt).toBe("2026-01-01T00:01:00.000Z");

      const callResponse = await app.inject({
        method: "POST",
        url: "/call",
        payload: { token, action: "post-message", input: { channel: "#general", text: "hi" } },
      });
      expect(callResponse.statusCode).toBe(200);
      expect(callResponse.json().result).toEqual({ id: "msg_1", channel: "#general", text: "hi" });
      expect(slack.messages).toHaveLength(1);

      // Advance past the token's 60s TTL: the same token must now be rejected.
      clock.set("2026-01-01T00:01:01Z");
      const expiredCall = await app.inject({
        method: "POST",
        url: "/call",
        payload: {
          token,
          action: "post-message",
          input: { channel: "#general", text: "too late" },
        },
      });
      expect(expiredCall.statusCode).toBe(401);
      expect(expiredCall.json().error).toEqual({ code: "INVALID_TOKEN", reason: "EXPIRED" });
      expect(slack.messages).toHaveLength(1);

      // A fresh token request succeeds — the agent must ask again, not reuse the old token.
      const freshTokenResponse = await app.inject({
        method: "POST",
        url: "/tokens",
        payload: { tool: "mock-slack", action: "post-message", credential },
      });
      expect(freshTokenResponse.statusCode).toBe(200);
      const freshCall = await app.inject({
        method: "POST",
        url: "/call",
        payload: {
          token: freshTokenResponse.json().token,
          action: "post-message",
          input: { channel: "#general", text: "back again" },
        },
      });
      expect(freshCall.statusCode).toBe(200);
      expect(slack.messages).toHaveLength(2);
    });
  });

  it("404s a token request for a tool with no stored credential", async () => {
    await withRegisteredAgent(4502, async (credential) => {
      const app = await buildServer({ db: vaultDb, cipher });
      const response = await app.inject({
        method: "POST",
        url: "/tokens",
        payload: { tool: "no-such-tool", action: "whatever", credential },
      });
      expect(response.statusCode).toBe(404);
    });
  });

  it("400s a malformed /call request", async () => {
    const app = await buildServer({ db: vaultDb, cipher });
    const response = await app.inject({ method: "POST", url: "/call", payload: { action: "x" } });
    expect(response.statusCode).toBe(400);
  });

  it("400s a malformed /credentials request", async () => {
    const app = await buildServer({ db: vaultDb, cipher });
    const response = await app.inject({
      method: "POST",
      url: "/credentials",
      payload: { tool: "" },
    });
    expect(response.statusCode).toBe(400);
  });

  it("400s a malformed /tokens request", async () => {
    const app = await buildServer({ db: vaultDb, cipher });
    const response = await app.inject({ method: "POST", url: "/tokens", payload: { tool: "x" } });
    expect(response.statusCode).toBe(400);
  });

  it("502s when the underlying connector rejects the call", async () => {
    await withRegisteredAgent(4503, async (credential) => {
      const app = await buildServer({
        db: vaultDb,
        cipher,
        connectors: [createMockDatabaseConnector()],
      });

      await app.inject({
        method: "POST",
        url: "/credentials",
        payload: { tool: "mock-database", secret: "unused-by-the-mock" },
      });
      const tokenResponse = await app.inject({
        method: "POST",
        url: "/tokens",
        payload: { tool: "mock-database", action: "query", credential },
      });
      const { token } = tokenResponse.json();

      const callResponse = await app.inject({
        method: "POST",
        url: "/call",
        payload: { token, action: "query", input: { table: "no-such-table" } },
      });

      expect(callResponse.statusCode).toBe(502);
      expect(callResponse.json().error.code).toBe("UPSTREAM_ERROR");
    });
  });
});

import { fixedClock } from "@custos/testing";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { generateApiKey } from "./api-key.js";
import { createApiKeyAuthenticator } from "./authenticator.js";
import { principalOf, requireScope } from "./fastify.js";
import { createLockout } from "./lockout.js";
import type { ApiKeyRow } from "./schema.js";

const clock = fixedClock("2026-10-02T12:00:00.000Z");
const UNAUTHORIZED = { error: { code: "UNAUTHORIZED" } };

function setup(maxFailures = 10) {
  const valid = generateApiKey("operator");
  const expired = generateApiKey("operator");
  const row = (id: string, secretHash: string, expiresAt: string): ApiKeyRow => ({
    id,
    kind: "operator",
    name: "lakshya",
    scopes: ["policies:write"],
    secretHash,
    createdAt: new Date("2026-10-01T00:00:00.000Z"),
    expiresAt: new Date(expiresAt),
    revokedAt: null,
  });
  const rows = new Map([
    [valid.id, row(valid.id, valid.secretHash, "2026-12-31T00:00:00.000Z")],
    [expired.id, row(expired.id, expired.secretHash, "2026-10-01T00:00:00.000Z")],
  ]);
  const authenticator = createApiKeyAuthenticator({
    keys: { findById: async (id) => rows.get(id) ?? null },
    clock,
  });
  const lockout = createLockout({ clock, maxFailures });

  const app = Fastify();
  app.post(
    "/policies",
    { preHandler: requireScope({ authenticator, lockout, scope: "policies:write" }) },
    async (request) => ({ by: principalOf(request).name }),
  );
  app.post(
    "/credentials",
    { preHandler: requireScope({ authenticator, lockout, scope: "credentials:write" }) },
    async () => ({ stored: true }),
  );
  app.get("/unguarded", async (request) => principalOf(request));
  return { app, valid: valid.token, expired: expired.token };
}

const post = (url: string, token?: string) => ({
  method: "POST" as const,
  url,
  headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
});

describe("requireScope", () => {
  it("lets a key with the scope through and exposes its principal", async () => {
    const { app, valid } = setup();
    const response = await app.inject(post("/policies", valid));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ by: "lakshya" });
  });

  it("refuses unauthenticated, wrongly-scoped and expired keys with one uniform error", async () => {
    const { app, valid, expired } = setup();
    const responses = await Promise.all([
      app.inject(post("/policies")),
      app.inject(post("/policies", "garbage")),
      app.inject(post("/policies", expired)),
      app.inject(post("/credentials", valid)),
    ]);
    for (const response of responses) {
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual(UNAUTHORIZED);
    }
  });

  it("locks out a source after repeated failures, even for a valid key", async () => {
    const { app, valid } = setup(3);
    for (let i = 0; i < 3; i += 1) await app.inject(post("/policies", "garbage"));
    const response = await app.inject(post("/policies", valid));
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(UNAUTHORIZED);
  });

  it("doesn't count a valid key's missing scope towards the lockout", async () => {
    const { app, valid } = setup(2);
    await app.inject(post("/credentials", valid));
    await app.inject(post("/credentials", valid));
    expect((await app.inject(post("/policies", valid))).statusCode).toBe(200);
  });

  it("never echoes the presented key in the response", async () => {
    const { app, expired } = setup();
    const response = await app.inject(post("/policies", expired));
    expect(response.body).not.toContain(expired);
  });

  it("treats principalOf on an unguarded route as a programmer error", async () => {
    const { app } = setup();
    const response = await app.inject({ method: "GET", url: "/unguarded" });
    expect(response.statusCode).toBe(500);
  });
});

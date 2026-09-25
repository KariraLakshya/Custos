import type { SignedCredential } from "@custos/core";
import {
  buildRegistrationRequest,
  createLocalKeyProvider,
  createLocalSecretCipher,
  ok,
} from "@custos/core";
import {
  createMockDatabaseConnector,
  createMockSlackConnector,
  type Connector,
} from "@custos/connectors";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import {
  buildServer as buildRevocationServer,
  createDb as createRevocationDb,
} from "@custos/revocation";
import { mutableClock } from "@custos/testing";
import type { FastifyInstance } from "fastify";
import { afterAll, describe, expect, it } from "vitest";
import { createDb } from "./db/client.js";
import { buildServer } from "./server.js";
import type { RevocationCache } from "./revocation/cache.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const vaultDb = createDb(databaseUrl);
const identityDb = createIdentityDb(databaseUrl);
const revocationDb = createRevocationDb(databaseUrl);
const cipher = createLocalSecretCipher(new Uint8Array(32).fill(11));

afterAll(async () => {
  await vaultDb.$client.end();
  await identityDb.$client.end();
  await revocationDb.$client.end();
});

/**
 * Stands in for the revocation service during registration, so vault tests
 * need only identity in-process. Indexes are unique per call.
 */
let nextStatusListIndex = 100_000;
const fakeStatusAllocator = {
  allocate: async () =>
    ok({
      statusListIndex: nextStatusListIndex++,
      statusListCredential: "http://127.0.0.1:4503/status/revocation",
    }),
};

/**
 * A revocation view that is fresh and empty — the Phase 2 baseline. The real
 * cache starts stale and denies everything until its first resync, which is
 * correct but is not what these tests are exercising.
 */
/** The agent's identity is its credential's subject; the issuer is the identity service (ADR 0007). */
function agentDidOf(credential: SignedCredential): string {
  return (credential.credentialSubject as { id: string }).id;
}

function testIssuerKey() {
  return {
    keyProvider: createLocalKeyProvider({ importedKeys: { issuer: new Uint8Array(32).fill(21) } }),
    keyId: "issuer",
  };
}

/** Registers an agent against the identity service on `port`, proving possession of a fresh key. */
async function registerAgentAt(port: number): Promise<SignedCredential> {
  const request = await buildRegistrationRequest({
    audience: `did:web:127.0.0.1%3A${port}`,
    now: new Date(),
  });
  const response = await fetch(`http://127.0.0.1:${port}/agents`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request.body),
  });
  const { credential } = (await response.json()) as { credential: SignedCredential };
  return credential;
}

function freshEmptyRevocationCache(): RevocationCache {
  return {
    isRevoked: () => false,
    isStale: () => false,
    status: () => ({ revokedCount: 0, freshAsOf: new Date().toISOString(), stale: false }),
    acceptTombstone: async () => ok("noop"),
    resync: async () => ok(0),
  };
}

async function withRegisteredAgent<T>(
  port: number,
  run: (credential: SignedCredential) => Promise<T>,
): Promise<T> {
  const app: FastifyInstance = await buildIdentityServer({
    db: identityDb,
    didDomain: `127.0.0.1:${port}`,
    issuerKey: testIssuerKey(),
    statusAllocator: fakeStatusAllocator,
  });
  await app.listen({ port, host: "127.0.0.1" });
  try {
    return await run(await registerAgentAt(port));
  } finally {
    await app.close();
  }
}

/**
 * Boots real identity, revocation, and vault instances in-process, wired
 * together exactly as production is (revocation URLs, no injected fakes),
 * so the vault's default `createRevocationCache` path and its `/revocations`
 * routes run for real rather than through `freshEmptyRevocationCache()`.
 */
async function withPhase3Stack<T>(
  ports: { readonly identity: number; readonly revocation: number; readonly vault: number },
  connectors: readonly Connector[],
  run: (stack: {
    readonly identityApp: FastifyInstance;
    readonly revocationApp: FastifyInstance;
    readonly vaultApp: FastifyInstance;
    readonly register: () => Promise<SignedCredential>;
    readonly revoke: (agentId: string, reason?: string) => Promise<Response>;
  }) => Promise<T>,
): Promise<T> {
  const revocationUrl = `http://127.0.0.1:${ports.revocation}`;
  const revocationIssuerDid = `did:web:127.0.0.1%3A${ports.revocation}`;
  const vaultUrl = `http://127.0.0.1:${ports.vault}`;

  const revocationApp: FastifyInstance = await buildRevocationServer({
    db: revocationDb,
    didDomain: `127.0.0.1:${ports.revocation}`,
    subscriberUrls: [vaultUrl],
  });
  await revocationApp.listen({ port: ports.revocation, host: "127.0.0.1" });

  const identityApp: FastifyInstance = await buildIdentityServer({
    db: identityDb,
    didDomain: `127.0.0.1:${ports.identity}`,
    issuerKey: testIssuerKey(),
    revocationUrl,
  });
  await identityApp.listen({ port: ports.identity, host: "127.0.0.1" });

  const vaultApp = await buildServer({
    db: vaultDb,
    cipher,
    connectors,
    revocationUrl,
    revocationIssuerDid,
    trustedIssuerDid: `did:web:127.0.0.1%3A${ports.identity}`,
    revocationResyncIntervalMs: 5_000,
  });
  await vaultApp.listen({ port: ports.vault, host: "127.0.0.1" });

  try {
    return await run({
      identityApp,
      revocationApp,
      vaultApp,
      register: () => registerAgentAt(ports.identity),
      revoke: async (agentId, reason) =>
        fetch(`${revocationUrl}/revocations`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(reason ? { agentId, reason } : { agentId }),
        }),
    });
  } finally {
    await vaultApp.close();
    await identityApp.close();
    await revocationApp.close();
  }
}

describe("vault service", () => {
  it("responds to /health", async () => {
    const app = await buildServer({ db: vaultDb, cipher, revocation: freshEmptyRevocationCache() });
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
        trustedIssuerDid: credential.issuer,
        revocation: freshEmptyRevocationCache(),
        connectors: [slack as Connector],
        clock,
      });

      const seed = await app.inject({
        method: "POST",
        url: "/credentials",
        payload: { tool: "mock-slack", secret: "xoxb-fake-bot-token" },
      });
      expect(seed.statusCode).toBe(201);

      const grant = await app.inject({
        method: "POST",
        url: "/policies",
        payload: { agentId: agentDidOf(credential), tool: "mock-slack" },
      });
      expect(grant.statusCode).toBe(201);

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
      const app = await buildServer({
        db: vaultDb,
        cipher,
        trustedIssuerDid: credential.issuer,
        revocation: freshEmptyRevocationCache(),
      });
      const response = await app.inject({
        method: "POST",
        url: "/tokens",
        payload: { tool: "no-such-tool", action: "whatever", credential },
      });
      expect(response.statusCode).toBe(404);
    });
  });

  it("400s a malformed /call request", async () => {
    const app = await buildServer({ db: vaultDb, cipher, revocation: freshEmptyRevocationCache() });
    const response = await app.inject({ method: "POST", url: "/call", payload: { action: "x" } });
    expect(response.statusCode).toBe(400);
  });

  it("400s a malformed /credentials request", async () => {
    const app = await buildServer({ db: vaultDb, cipher, revocation: freshEmptyRevocationCache() });
    const response = await app.inject({
      method: "POST",
      url: "/credentials",
      payload: { tool: "" },
    });
    expect(response.statusCode).toBe(400);
  });

  it("400s a malformed /tokens request", async () => {
    const app = await buildServer({ db: vaultDb, cipher, revocation: freshEmptyRevocationCache() });
    const response = await app.inject({ method: "POST", url: "/tokens", payload: { tool: "x" } });
    expect(response.statusCode).toBe(400);
  });

  it("400s a malformed /policies request", async () => {
    const app = await buildServer({ db: vaultDb, cipher, revocation: freshEmptyRevocationCache() });
    const response = await app.inject({ method: "POST", url: "/policies", payload: { tool: "x" } });
    expect(response.statusCode).toBe(400);
  });

  describe("authorization", () => {
    it("denies a token request for a verified agent with no policy grant", async () => {
      await withRegisteredAgent(4504, async (credential) => {
        const app = await buildServer({
          db: vaultDb,
          cipher,
          trustedIssuerDid: credential.issuer,
          revocation: freshEmptyRevocationCache(),
          connectors: [createMockSlackConnector()],
          auditReporter: { report: () => {} },
        });
        await app.inject({
          method: "POST",
          url: "/credentials",
          payload: { tool: "mock-slack", secret: "xoxb-fake-bot-token" },
        });

        const response = await app.inject({
          method: "POST",
          url: "/tokens",
          payload: { tool: "mock-slack", action: "post-message", credential },
        });
        expect(response.statusCode).toBe(403);
        expect(response.json().error).toEqual({
          code: "POLICY_DENIED",
          agentId: agentDidOf(credential),
          tool: "mock-slack",
        });
      });
    });

    it("grants access via /policies, then allows the same agent/tool pair", async () => {
      await withRegisteredAgent(4505, async (credential) => {
        const app = await buildServer({
          db: vaultDb,
          cipher,
          trustedIssuerDid: credential.issuer,
          revocation: freshEmptyRevocationCache(),
          connectors: [createMockSlackConnector()],
        });
        await app.inject({
          method: "POST",
          url: "/credentials",
          payload: { tool: "mock-slack", secret: "xoxb-fake-bot-token" },
        });
        const grant = await app.inject({
          method: "POST",
          url: "/policies",
          payload: { agentId: agentDidOf(credential), tool: "mock-slack" },
        });
        expect(grant.statusCode).toBe(201);

        const response = await app.inject({
          method: "POST",
          url: "/tokens",
          payload: { tool: "mock-slack", action: "post-message", credential },
        });
        expect(response.statusCode).toBe(200);
      });
    });
  });

  describe("audit reporting", () => {
    it("reports a denied token request", async () => {
      await withRegisteredAgent(4506, async (credential) => {
        const events: unknown[] = [];
        const app = await buildServer({
          db: vaultDb,
          cipher,
          trustedIssuerDid: credential.issuer,
          revocation: freshEmptyRevocationCache(),
          connectors: [createMockSlackConnector()],
          auditReporter: { report: (event) => events.push(event) },
        });
        await app.inject({
          method: "POST",
          url: "/credentials",
          payload: { tool: "mock-slack", secret: "xoxb-fake-bot-token" },
        });

        await app.inject({
          method: "POST",
          url: "/tokens",
          payload: { tool: "mock-slack", action: "post-message", credential },
        });

        expect(events).toEqual([
          {
            agentDid: agentDidOf(credential),
            tool: "mock-slack",
            action: "post-message",
            dataCategories: ["messaging-content"],
            policy: { rule: "agent-tool-allowlist", decision: "deny" },
            reason: "no policy grant for this agent/tool pair",
          },
        ]);
      });
    });

    it("reports both an allowed and a denied tool call", async () => {
      await withRegisteredAgent(4507, async (credential) => {
        const events: unknown[] = [];
        const app = await buildServer({
          db: vaultDb,
          cipher,
          trustedIssuerDid: credential.issuer,
          revocation: freshEmptyRevocationCache(),
          connectors: [createMockSlackConnector()],
          auditReporter: { report: (event) => events.push(event) },
        });
        await app.inject({
          method: "POST",
          url: "/credentials",
          payload: { tool: "mock-slack", secret: "xoxb-fake-bot-token" },
        });
        await app.inject({
          method: "POST",
          url: "/policies",
          payload: { agentId: agentDidOf(credential), tool: "mock-slack" },
        });
        const tokenResponse = await app.inject({
          method: "POST",
          url: "/tokens",
          payload: { tool: "mock-slack", action: "post-message", credential },
        });
        const { token } = tokenResponse.json();

        await app.inject({
          method: "POST",
          url: "/call",
          payload: { token, action: "post-message", input: { channel: "#general", text: "hi" } },
        });
        // Reusing the same token for a mismatched action is a second, denied action.
        await app.inject({
          method: "POST",
          url: "/call",
          payload: { token, action: "delete-everything", input: {} },
        });

        expect(events).toEqual([
          {
            agentDid: agentDidOf(credential),
            tool: "mock-slack",
            action: "post-message",
            dataCategories: ["messaging-content"],
            policy: { rule: "scoped-token", decision: "allow" },
          },
          {
            agentDid: agentDidOf(credential),
            tool: "mock-slack",
            action: "delete-everything",
            dataCategories: [],
            policy: { rule: "token-scope", decision: "deny" },
            reason: 'token is scoped to action "post-message"',
          },
        ]);
      });
    });
  });

  it("502s when the underlying connector rejects the call", async () => {
    await withRegisteredAgent(4503, async (credential) => {
      const app = await buildServer({
        db: vaultDb,
        cipher,
        trustedIssuerDid: credential.issuer,
        revocation: freshEmptyRevocationCache(),
        connectors: [createMockDatabaseConnector()],
      });

      await app.inject({
        method: "POST",
        url: "/credentials",
        payload: { tool: "mock-database", secret: "unused-by-the-mock" },
      });
      await app.inject({
        method: "POST",
        url: "/policies",
        payload: { agentId: agentDidOf(credential), tool: "mock-database" },
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

  describe("revocation", () => {
    it("reports a fresh-boot vault as stale before its first resync", async () => {
      // No revocationResyncIntervalMs: the real cache is built but never
      // synced, so it must not silently claim to know who is revoked.
      const app = await buildServer({
        db: vaultDb,
        cipher,
        revocationUrl: "http://127.0.0.1:1",
        revocationIssuerDid: "did:web:127.0.0.1%3A1",
      });
      const response = await app.inject({ method: "GET", url: "/revocations" });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ revokedCount: 0, freshAsOf: null, stale: true });
    });

    it(
      "cuts a revoked agent off within one call: token issuance denies it, " +
        "the tool adapter itself refuses it, and the vault reports it as revoked",
      async () => {
        const slack = createMockSlackConnector();
        await withPhase3Stack(
          { identity: 4601, revocation: 4602, vault: 4603 },
          [slack as Connector],
          async ({ vaultApp: app, register, revoke }) => {
            const credential = await register();
            // did:web:127.0.0.1%3A4601:agents:<uuid> — the id is the final
            // colon-separated segment.
            const agentId = agentDidOf(credential).split(":").pop()!;

            await app.inject({
              method: "POST",
              url: "/credentials",
              payload: { tool: "mock-slack", secret: "xoxb-fake-bot-token" },
            });
            await app.inject({
              method: "POST",
              url: "/policies",
              payload: { agentId: agentDidOf(credential), tool: "mock-slack" },
            });

            // Works before revocation.
            const tokenBefore = await app.inject({
              method: "POST",
              url: "/tokens",
              payload: { tool: "mock-slack", action: "post-message", credential },
            });
            expect(tokenBefore.statusCode).toBe(200);

            const revokeResponse = await revoke(agentId, "compromised");
            expect(revokeResponse.status).toBe(200);
            const revoked = (await revokeResponse.json()) as {
              agentDid: string;
              broadcast: { delivered: number; failed: readonly string[] };
            };
            // The tombstone push is synchronous with this response: by the
            // time /revocations returns, the vault has already applied it.
            expect(revoked.broadcast).toEqual({ delivered: 1, failed: [] });

            // Postgres persists across test runs, so other revoked agents
            // from earlier runs may already be in this shared DB — only the
            // freshness and "at least this one" are guaranteed here.
            const statusAfter = await app.inject({ method: "GET", url: "/revocations" });
            const status = statusAfter.json() as { revokedCount: number; stale: boolean };
            expect(status.stale).toBe(false);
            expect(status.revokedCount).toBeGreaterThanOrEqual(1);

            // Token issuance now refuses the revoked agent.
            const tokenAfter = await app.inject({
              method: "POST",
              url: "/tokens",
              payload: { tool: "mock-slack", action: "post-message", credential },
            });
            expect(tokenAfter.statusCode).toBe(403);
            expect(tokenAfter.json().error.code).toBe("AGENT_REVOKED");

            // The tool call with the pre-revocation token is also refused —
            // the hot path re-checks revocation on every call, not just at
            // issuance, so a 60s-old token cannot be used to dodge it.
            const callAfter = await app.inject({
              method: "POST",
              url: "/call",
              payload: {
                token: tokenBefore.json().token,
                action: "post-message",
                input: { channel: "#general", text: "should not arrive" },
              },
            });
            expect(callAfter.statusCode).toBe(403);
            expect(callAfter.json().error.code).toBe("AGENT_REVOKED");
            expect(slack.messages).toHaveLength(0);

            // "Adapters honour revocation": the fanout genuinely reached the
            // connector, which now refuses this agent even if called directly.
            const direct = await slack.call({
              action: "post-message",
              input: { channel: "#general", text: "direct" },
              credential: "xoxb-fake-bot-token",
              agentId: revoked.agentDid,
            });
            expect(direct.ok).toBe(false);
            if (!direct.ok) expect(direct.error.code).toBe("AGENT_REVOKED");
          },
        );
      },
    );

    it("400s a malformed tombstone push", async () => {
      const app = await buildServer({
        db: vaultDb,
        cipher,
        revocation: freshEmptyRevocationCache(),
      });
      const response = await app.inject({ method: "POST", url: "/revocations", payload: {} });
      expect(response.statusCode).toBe(400);
    });

    it("401s a tombstone that fails to verify", async () => {
      // The issuer's key is resolved before the signature is checked, so a
      // live revocation service is needed to reach the verify step at all.
      await withPhase3Stack(
        { identity: 4611, revocation: 4612, vault: 4613 },
        [],
        async ({ vaultApp }) => {
          const response = await vaultApp.inject({
            method: "POST",
            url: "/revocations",
            payload: { tombstone: "not-a-real-tombstone" },
          });
          expect(response.statusCode).toBe(401);
          expect(response.json().error.code).toBe("INVALID_TOMBSTONE");
        },
      );
    });

    it("502s a tombstone push when the issuer cannot be resolved to verify it", async () => {
      const app = await buildServer({
        db: vaultDb,
        cipher,
        revocationUrl: "http://127.0.0.1:1",
        revocationIssuerDid: "did:web:127.0.0.1%3A1",
      });
      const response = await app.inject({
        method: "POST",
        url: "/revocations",
        // Shape doesn't matter: the issuer key is resolved before the
        // signature is even checked, and that resolution fails first.
        payload: { tombstone: "claims.signature" },
      });
      expect(response.statusCode).toBe(502);
      expect(response.json().error.code).toBe("UNVERIFIABLE_ISSUER");
    });
  });
});

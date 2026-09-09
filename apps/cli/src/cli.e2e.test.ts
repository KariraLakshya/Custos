import { createServer, type Server } from "node:http";
import { createLocalSecretCipher, ok, type SignedCredential } from "@custos/core";
import {
  createMockDatabaseConnector,
  createMockSlackConnector,
  createStripeConnector,
  type Connector,
} from "@custos/connectors";
import { buildServer, createDb } from "@custos/identity";
import {
  buildServer as buildRevocationServer,
  createDb as createRevocationDb,
} from "@custos/revocation";
import { mutableClock } from "@custos/testing";
import { buildServer as buildVaultServer, createDb as createVaultDb } from "@custos/vault";
import { afterAll, describe, expect, it } from "vitest";
import { deprovisionAgent } from "./deprovision.js";
import { registerAgent } from "./register.js";
import { useTool } from "./use.js";
import { verifyCredentialIndependently } from "./verify.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);
const vaultDb = createVaultDb(databaseUrl);
const revocationDb = createRevocationDb(databaseUrl);
const vaultCipher = createLocalSecretCipher(new Uint8Array(32).fill(21));

afterAll(async () => {
  await db.$client.end();
  await vaultDb.$client.end();
  await revocationDb.$client.end();
});

/**
 * Stands in for the revocation service, so the register/verify tests below
 * (which exercise identity in isolation, not revocation) don't need one
 * running. Matches the pattern in services/identity's and services/vault's
 * own test files.
 */
let nextStatusListIndex = 900_000;
const fakeStatusAllocator = {
  allocate: async () =>
    ok({
      statusListIndex: nextStatusListIndex++,
      statusListCredential: "http://127.0.0.1:4503/status/revocation",
    }),
};

async function withRunningIdentityService<T>(
  port: number,
  run: (identityUrl: string) => Promise<T>,
): Promise<T> {
  const app = buildServer({
    db,
    didDomain: `127.0.0.1:${port}`,
    statusAllocator: fakeStatusAllocator,
  });
  await app.listen({ port, host: "127.0.0.1" });
  try {
    return await run(`http://127.0.0.1:${port}`);
  } finally {
    await app.close();
  }
}

/**
 * Boots real identity, revocation, and vault services wired together exactly
 * as production is — identity reserves a status list index against the real
 * revocation service, and the vault's revocation cache is the real one, not
 * a fake, so a `custos deprovision` genuinely propagates end to end.
 */
async function withPhase3Stack<T>(
  ports: { readonly identity: number; readonly revocation: number; readonly vault: number },
  connectors: readonly Connector[],
  run: (urls: {
    readonly identityUrl: string;
    readonly revocationUrl: string;
    readonly vaultUrl: string;
  }) => Promise<T>,
  vaultClock?: { now(): Date },
): Promise<T> {
  const identityUrl = `http://127.0.0.1:${ports.identity}`;
  const revocationUrl = `http://127.0.0.1:${ports.revocation}`;
  const vaultUrl = `http://127.0.0.1:${ports.vault}`;

  const revocationApp = await buildRevocationServer({
    db: revocationDb,
    didDomain: `127.0.0.1:${ports.revocation}`,
    subscriberUrls: [vaultUrl],
  });
  await revocationApp.listen({ port: ports.revocation, host: "127.0.0.1" });

  const identityApp = buildServer({
    db,
    didDomain: `127.0.0.1:${ports.identity}`,
    revocationUrl,
  });
  await identityApp.listen({ port: ports.identity, host: "127.0.0.1" });

  const vaultApp = await buildVaultServer({
    db: vaultDb,
    cipher: vaultCipher,
    connectors,
    revocationUrl,
    revocationIssuerDid: `did:web:127.0.0.1%3A${ports.revocation}`,
    revocationResyncIntervalMs: 5_000,
    // Generous on purpose: some tests here jump a mutableClock far ahead to
    // simulate a scoped token's 60s TTL expiry, and that same clock also
    // drives the revocation cache's own staleness check (both are `now:
    // clock.now()`). A wide bound keeps that clock jump from tripping
    // revocation staleness, which none of these tests are exercising —
    // bounded staleness itself is covered in services/vault's own tests.
    revocationMaxStalenessMs: 10 * 60_000,
    ...(vaultClock ? { clock: vaultClock } : {}),
  });
  await vaultApp.listen({ port: ports.vault, host: "127.0.0.1" });

  try {
    return await run({ identityUrl, revocationUrl, vaultUrl });
  } finally {
    await vaultApp.close();
    await identityApp.close();
    await revocationApp.close();
  }
}

describe("custos register + verify (end-to-end lifecycle)", () => {
  it("registers an agent via the CLI's HTTP call and independently verifies the issued credential", async () => {
    const outcome = await withRunningIdentityService(4101, async (identityUrl) => {
      const registered = await registerAgent(identityUrl);
      return verifyCredentialIndependently(registered.credential as SignedCredential);
    });

    expect(outcome).toEqual({ verified: true });
  });

  it("rejects a credential tampered with after registration", async () => {
    const outcome = await withRunningIdentityService(4102, async (identityUrl) => {
      const registered = await registerAgent(identityUrl);
      const tampered = structuredClone(registered.credential) as SignedCredential & {
        credentialSubject: { id: string };
      };
      tampered.credentialSubject.id = "did:web:attacker.example";
      return verifyCredentialIndependently(tampered);
    });

    expect(outcome.verified).toBe(false);
  });
});

describe("custos use (Phase 2: request a scoped token, call the tool, watch it expire)", () => {
  it("registers an agent, obtains a 60s token, and successfully calls a tool through the vault", async () => {
    await withPhase3Stack(
      { identity: 4901, revocation: 4902, vault: 4903 },
      [createMockDatabaseConnector()],
      async ({ identityUrl, vaultUrl }) => {
        const registered = await registerAgent(identityUrl);

        await fetch(new URL("/credentials", vaultUrl), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tool: "mock-database", secret: "unused-by-the-mock" }),
        });

        const outcome = await useTool({
          vaultUrl,
          credential: registered.credential as SignedCredential,
          tool: "mock-database",
          action: "query",
          input: { table: "customers" },
        });

        expect(outcome.result).toHaveLength(2);
      },
    );
  });

  it("rejects a token once it expires — the agent must request a fresh one to call again", async () => {
    const clock = mutableClock("2026-01-01T00:00:00Z");
    await withPhase3Stack(
      { identity: 4911, revocation: 4912, vault: 4913 },
      [createMockDatabaseConnector()],
      async ({ identityUrl, vaultUrl }) => {
        const registered = await registerAgent(identityUrl);

        await fetch(new URL("/credentials", vaultUrl), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tool: "mock-database", secret: "unused-by-the-mock" }),
        });
        const requestToken = () =>
          fetch(new URL("/tokens", vaultUrl), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              tool: "mock-database",
              action: "query",
              credential: registered.credential,
            }),
          }).then((response) => response.json() as Promise<{ token: string }>);
        const call = (token: string) =>
          fetch(new URL("/call", vaultUrl), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ token, action: "query", input: { table: "customers" } }),
          });

        const { token: originalToken } = await requestToken();
        expect((await call(originalToken)).status).toBe(200);

        clock.set("2026-01-01T00:01:01Z");
        expect((await call(originalToken)).status).toBe(401);

        const { token: freshToken } = await requestToken();
        expect((await call(freshToken)).status).toBe(200);
      },
      clock,
    );
  });
});

/** A minimal local stand-in for the Stripe API, mirroring stripe.test.ts's pattern. */
async function withStandInStripe<T>(run: (baseUrl: string) => Promise<T>): Promise<T> {
  const server: Server = createServer((req, res) => {
    if (req.url?.startsWith("/customers")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ object: "list", data: [{ id: "cus_1" }] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected a bound port");
  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

describe("custos deprovision (Phase 3: the revocation demo)", () => {
  it(
    "an agent actively using three tools is cut off from all three within about a second " +
      "of a single `custos deprovision` call",
    async () => {
      await withStandInStripe(async (stripeBaseUrl) => {
        const slack = createMockSlackConnector();
        const database = createMockDatabaseConnector();
        const stripe = createStripeConnector({ baseUrl: stripeBaseUrl });

        await withPhase3Stack(
          { identity: 4801, revocation: 4802, vault: 4803 },
          [slack, database, stripe],
          async ({ identityUrl, revocationUrl, vaultUrl }) => {
            const registered = await registerAgent(identityUrl);
            const credential = registered.credential as SignedCredential;

            for (const [tool, secret] of [
              ["mock-slack", "xoxb-fake"],
              ["mock-database", "unused-by-the-mock"],
              ["stripe", "sk_test_fake"],
            ] as const) {
              const seeded = await fetch(new URL("/credentials", vaultUrl), {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ tool, secret }),
              });
              expect(seeded.status).toBe(201);
            }

            // The agent's active session: one 60s token per tool, already
            // spent once each — this is what "actively calling three tools"
            // means, not a fresh request made after revocation.
            const sessions = [
              {
                tool: "mock-slack",
                action: "post-message",
                input: { channel: "#ops", text: "hi" },
              },
              { tool: "mock-database", action: "query", input: { table: "customers" } },
              { tool: "stripe", action: "list-customers", input: undefined },
            ] as const;

            const tokens = await Promise.all(
              sessions.map(async ({ tool, action }) => {
                const response = await fetch(new URL("/tokens", vaultUrl), {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify({ tool, action, credential }),
                });
                expect(response.status).toBe(200);
                return (await response.json()) as { token: string };
              }),
            );

            const callTool = (index: number) =>
              fetch(new URL("/call", vaultUrl), {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({
                  token: tokens[index]!.token,
                  action: sessions[index]!.action,
                  input: sessions[index]!.input,
                }),
              });

            // All three genuinely work before deprovision.
            const before = await Promise.all(sessions.map((_, i) => callTool(i)));
            for (const response of before) expect(response.status).toBe(200);

            const start = Date.now();
            const deprovisioned = await deprovisionAgent({ revocationUrl, agentId: registered.id });
            expect(deprovisioned.broadcast).toEqual({ delivered: 1, failed: [] });

            // The same session tokens the agent already holds — no new
            // request, no waiting — now fail at all three tools.
            const after = await Promise.all(sessions.map((_, i) => callTool(i)));
            const elapsedMs = Date.now() - start;

            for (const response of after) {
              expect(response.status).toBe(403);
              const body = (await response.json()) as { error: { code: string } };
              expect(body.error.code).toBe("AGENT_REVOKED");
            }
            expect(elapsedMs).toBeLessThan(1_000);

            // "Adapters honour revocation": the connectors themselves — not
            // only the vault's own gate — refuse this agent directly.
            const direct = await Promise.all([
              slack.call({
                action: "post-message",
                input: { channel: "#ops", text: "should not arrive" },
                credential: "xoxb-fake",
                agentId: deprovisioned.agentDid,
              }),
              database.call({
                action: "query",
                input: { table: "customers" },
                credential: "unused-by-the-mock",
                agentId: deprovisioned.agentDid,
              }),
              stripe.call({
                action: "list-customers",
                input: undefined,
                credential: "sk_test_fake",
                agentId: deprovisioned.agentDid,
              }),
            ]);
            for (const result of direct) {
              expect(result.ok).toBe(false);
              if (!result.ok) expect(result.error.code).toBe("AGENT_REVOKED");
            }
          },
        );
      });
    },
  );
});

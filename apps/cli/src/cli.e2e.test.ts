import { createLocalSecretCipher, type SignedCredential } from "@custos/core";
import { createMockDatabaseConnector } from "@custos/connectors";
import { buildServer, createDb } from "@custos/identity";
import { mutableClock } from "@custos/testing";
import { buildServer as buildVaultServer, createDb as createVaultDb } from "@custos/vault";
import { afterAll, describe, expect, it } from "vitest";
import { registerAgent } from "./register.js";
import { useTool } from "./use.js";
import { verifyCredentialIndependently } from "./verify.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);
const vaultDb = createVaultDb(databaseUrl);
const vaultCipher = createLocalSecretCipher(new Uint8Array(32).fill(21));

afterAll(async () => {
  await db.$client.end();
  await vaultDb.$client.end();
});

async function withRunningIdentityService<T>(
  port: number,
  run: (identityUrl: string) => Promise<T>,
): Promise<T> {
  const app = buildServer({ db, didDomain: `127.0.0.1:${port}` });
  await app.listen({ port, host: "127.0.0.1" });
  try {
    return await run(`http://127.0.0.1:${port}`);
  } finally {
    await app.close();
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
    await withRunningIdentityService(4601, async (identityUrl) => {
      const registered = await registerAgent(identityUrl);

      const app = await buildVaultServer({
        db: vaultDb,
        cipher: vaultCipher,
        connectors: [createMockDatabaseConnector()],
      });
      await app.listen({ port: 4602, host: "127.0.0.1" });
      try {
        await fetch("http://127.0.0.1:4602/credentials", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tool: "mock-database", secret: "unused-by-the-mock" }),
        });

        const outcome = await useTool({
          vaultUrl: "http://127.0.0.1:4602",
          credential: registered.credential as SignedCredential,
          tool: "mock-database",
          action: "query",
          input: { table: "customers" },
        });

        expect(outcome.result).toHaveLength(2);
      } finally {
        await app.close();
      }
    });
  });

  it("rejects a token once it expires — the agent must request a fresh one to call again", async () => {
    await withRunningIdentityService(4603, async (identityUrl) => {
      const registered = await registerAgent(identityUrl);

      const clock = mutableClock("2026-01-01T00:00:00Z");
      const app = await buildVaultServer({
        db: vaultDb,
        cipher: vaultCipher,
        connectors: [createMockDatabaseConnector()],
        clock,
      });
      await app.listen({ port: 4604, host: "127.0.0.1" });
      try {
        await fetch("http://127.0.0.1:4604/credentials", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tool: "mock-database", secret: "unused-by-the-mock" }),
        });
        const requestToken = () =>
          fetch("http://127.0.0.1:4604/tokens", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              tool: "mock-database",
              action: "query",
              credential: registered.credential,
            }),
          }).then((response) => response.json() as Promise<{ token: string }>);
        const call = (token: string) =>
          fetch("http://127.0.0.1:4604/call", {
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
      } finally {
        await app.close();
      }
    });
  });
});

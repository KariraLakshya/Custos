import type { SignedCredential } from "@custos/core";
import { buildServer, createDb } from "@custos/identity";
import { afterAll, describe, expect, it } from "vitest";
import { registerAgent } from "./register.js";
import { verifyCredentialIndependently } from "./verify.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);

afterAll(async () => {
  await db.$client.end();
});

async function withRunningIdentityService<T>(
  port: number,
  run: (identityUrl: string) => Promise<T>,
): Promise<T> {
  const app = buildServer({ db, didDomain: `localhost:${port}` });
  await app.listen({ port, host: "127.0.0.1" });
  try {
    return await run(`http://localhost:${port}`);
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

import { verifyCredential, type SignedCredential } from "@custos/core";
import { afterAll, describe, expect, it } from "vitest";
import { createDb } from "./db/client.js";
import { buildServer } from "./server.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);

afterAll(async () => {
  await db.$client.end();
});

describe("identity service", () => {
  it("responds to /health", async () => {
    const app = buildServer({ db });
    const response = await app.inject({ method: "GET", url: "/health" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "identity" });
  });

  it("registers an agent and independently verifies its issued credential", async () => {
    const app = buildServer({ db, didDomain: "identity.custos.example" });

    const registerResponse = await app.inject({ method: "POST", url: "/agents" });
    expect(registerResponse.statusCode).toBe(201);
    const registered = registerResponse.json();
    expect(registered.did).toBe(`did:web:identity.custos.example:agents:${registered.id}`);

    const didDocResponse = await app.inject({
      method: "GET",
      url: `/agents/${registered.id}/did.json`,
    });
    expect(didDocResponse.statusCode).toBe(200);
    const didDocument = didDocResponse.json();
    expect(didDocument).toEqual(registered.didDocument);

    const verified = await verifyCredential({
      credential: registered.credential as SignedCredential,
      didDocument,
    });
    expect(verified.ok).toBe(true);
  });

  it("rejects a tampered credential on independent verification", async () => {
    const app = buildServer({ db, didDomain: "identity.custos.example" });

    const registerResponse = await app.inject({ method: "POST", url: "/agents" });
    const registered = registerResponse.json();

    const tamperedCredential = structuredClone(registered.credential) as SignedCredential & {
      credentialSubject: { id: string };
    };
    tamperedCredential.credentialSubject.id = "did:web:attacker.example";

    const verified = await verifyCredential({
      credential: tamperedCredential,
      didDocument: registered.didDocument,
    });
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.error.code).toBe("SIGNATURE_INVALID");
  });

  it("404s a did.json request for an unknown agent id", async () => {
    const app = buildServer({ db });
    const response = await app.inject({
      method: "GET",
      url: "/agents/00000000-0000-0000-0000-000000000000/did.json",
    });
    expect(response.statusCode).toBe(404);
  });

  it("400s a did.json request for a malformed agent id", async () => {
    const app = buildServer({ db });
    const response = await app.inject({ method: "GET", url: "/agents/not-a-uuid/did.json" });
    expect(response.statusCode).toBe(400);
  });
});

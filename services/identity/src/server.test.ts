import { ok, err, verifyCredential, type SignedCredential } from "@custos/core";
import { afterAll, describe, expect, it } from "vitest";
import { createDb } from "./db/client.js";
import { buildServer } from "./server.js";
import type { StatusAllocator } from "./agents/status-allocator.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);

afterAll(async () => {
  await db.$client.end();
});

/**
 * Stands in for the revocation service, so identity's own tests do not need
 * it running. Hands out indexes from a counter, as the real service does.
 */
function fakeStatusAllocator(): StatusAllocator {
  let nextIndex = 0;
  return {
    allocate: async () =>
      ok({
        statusListIndex: nextIndex++,
        statusListCredential: "http://127.0.0.1:4503/status/revocation",
      }),
  };
}

const unreachableStatusAllocator: StatusAllocator = {
  allocate: async () =>
    err({ code: "STATUS_ALLOCATION_FAILED", reason: "revocation service unreachable" }),
};

function buildTestServer(options: { readonly didDomain?: string } = {}) {
  return buildServer({
    db,
    statusAllocator: fakeStatusAllocator(),
    ...(options.didDomain === undefined ? {} : { didDomain: options.didDomain }),
  });
}

describe("identity service", () => {
  it("responds to /health", async () => {
    const app = buildTestServer();
    const response = await app.inject({ method: "GET", url: "/health" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "identity" });
  });

  it("registers an agent and independently verifies its issued credential", async () => {
    const app = buildTestServer({ didDomain: "identity.custos.example" });

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
    const app = buildTestServer({ didDomain: "identity.custos.example" });

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

  it("embeds a revocation status entry in every issued credential", async () => {
    const app = buildTestServer({ didDomain: "identity.custos.example" });

    const registerResponse = await app.inject({ method: "POST", url: "/agents" });
    const registered = registerResponse.json();
    const credentialStatus = (registered.credential as SignedCredential).credentialStatus;

    expect(credentialStatus).toBeDefined();
    expect(credentialStatus?.type).toBe("BitstringStatusListEntry");
    expect(credentialStatus?.statusPurpose).toBe("revocation");
    expect(credentialStatus?.statusListCredential).toBe("http://127.0.0.1:4503/status/revocation");
    expect(typeof credentialStatus?.statusListIndex).toBe("string");
  });

  it("keeps the status entry inside the signature — tampering with it is detected", async () => {
    const app = buildTestServer({ didDomain: "identity.custos.example" });

    const registerResponse = await app.inject({ method: "POST", url: "/agents" });
    const registered = registerResponse.json();

    // Repointing a credential at an index that is not this agent's would let
    // a compromised agent dodge its own revocation bit.
    const tampered = structuredClone(registered.credential) as SignedCredential & {
      credentialStatus: { statusListIndex: string };
    };
    tampered.credentialStatus.statusListIndex = "999999";

    const verified = await verifyCredential({
      credential: tampered,
      didDocument: registered.didDocument,
    });
    expect(verified.ok).toBe(false);
  });

  // An agent that exists but has no status list entry could never be
  // revoked, so registration must fail rather than issue one.
  it("refuses to register an agent when the revocation service is unreachable", async () => {
    const app = buildServer({
      db,
      statusAllocator: unreachableStatusAllocator,
      didDomain: "identity.custos.example",
    });

    const response = await app.inject({ method: "POST", url: "/agents" });

    expect(response.statusCode).toBe(502);
    expect(response.json().error.code).toBe("STATUS_ALLOCATION_FAILED");
  });

  it("404s a did.json request for an unknown agent id", async () => {
    const app = buildTestServer();
    const response = await app.inject({
      method: "GET",
      url: "/agents/00000000-0000-0000-0000-000000000000/did.json",
    });
    expect(response.statusCode).toBe(404);
  });

  it("400s a did.json request for a malformed agent id", async () => {
    const app = buildTestServer();
    const response = await app.inject({ method: "GET", url: "/agents/not-a-uuid/did.json" });
    expect(response.statusCode).toBe(400);
  });
});

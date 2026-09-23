import { randomUUID } from "node:crypto";
import { verifyAuditRecord, type DidWebDocument } from "@custos/core";
import { fixedClock } from "@custos/testing";
import { afterAll, describe, expect, it } from "vitest";
import { createDb } from "./db/client.js";
import { buildServer } from "./server.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);

afterAll(async () => {
  await db.$client.end();
});

/** Public key of the service's own signing identity, from its DID document. */
function publicKeyFrom(didDocument: DidWebDocument): Uint8Array {
  const multibase = didDocument.verificationMethod[0].publicKeyMultibase;
  // Strip the multibase "z" prefix and the 2-byte multicodec ed25519-pub header.
  return decodeBase58(multibase.slice(1)).slice(2);
}

function decodeBase58(input: string): Uint8Array {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const bytes: number[] = [];
  for (const char of input) {
    let carry = ALPHABET.indexOf(char);
    if (carry < 0) throw new Error(`invalid base58 character: ${char}`);
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i]! * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of input) {
    if (char !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

describe("audit service", () => {
  it("responds to /health", async () => {
    const app = await buildServer({ db, didDomain: "127.0.0.1:4820" });
    const response = await app.inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "audit" });
  });

  it("publishes its own DID document", async () => {
    const app = await buildServer({ db, didDomain: "127.0.0.1:4821" });
    const response = await app.inject({ method: "GET", url: "/.well-known/did.json" });
    expect(response.statusCode).toBe(200);
    expect(response.json().id).toBe("did:web:127.0.0.1%3A4821");
  });

  it("400s a malformed /records report", async () => {
    const app = await buildServer({ db, didDomain: "127.0.0.1:4822" });
    const response = await app.inject({ method: "POST", url: "/records", payload: { tool: "x" } });
    expect(response.statusCode).toBe(400);
  });

  it("400s an invalid policy.decision", async () => {
    const app = await buildServer({ db, didDomain: "127.0.0.1:4823" });
    const response = await app.inject({
      method: "POST",
      url: "/records",
      payload: {
        agentDid: "did:web:localhost%3A4001:agents:a1",
        tool: "mock-slack",
        action: "post-message",
        dataCategories: [],
        policy: { rule: "x", decision: "maybe" },
      },
    });
    expect(response.statusCode).toBe(400);
  });

  it("stores a reported record and returns it signed and independently verifiable via GET /records", async () => {
    const clock = fixedClock("2026-09-12T10:00:00.000Z");
    const app = await buildServer({ db, didDomain: "127.0.0.1:4824", clock });
    const agentDid = `did:web:127.0.0.1%3A4824:agents:${randomUUID()}`;

    const posted = await app.inject({
      method: "POST",
      url: "/records",
      payload: {
        agentDid,
        tool: "mock-slack",
        action: "post-message",
        dataCategories: ["messaging-content"],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
      },
    });
    expect(posted.statusCode).toBe(201);

    const pulled = await app.inject({
      method: "GET",
      url: `/records?agentId=${encodeURIComponent(agentDid)}`,
    });
    const { records } = pulled.json() as { records: readonly string[] };
    expect(records).toHaveLength(1);

    const didResponse = await app.inject({ method: "GET", url: "/.well-known/did.json" });
    const publicKey = publicKeyFrom(didResponse.json() as DidWebDocument);

    const verified = verifyAuditRecord({ record: records[0]!, publicKey });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.value).toEqual({
        agentDid,
        authorityChain: [agentDid],
        tool: "mock-slack",
        action: "post-message",
        dataCategories: ["messaging-content"],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
        recordedAt: "2026-09-12T10:00:00.000Z",
      });
    }
  });

  it("rejects a record verified against an unrelated service's key", async () => {
    const app = await buildServer({ db, didDomain: "127.0.0.1:4825" });
    const other = await buildServer({ db, didDomain: "127.0.0.1:4826" });
    const agentDid = `did:web:127.0.0.1%3A4825:agents:${randomUUID()}`;

    await app.inject({
      method: "POST",
      url: "/records",
      payload: {
        agentDid,
        tool: "mock-slack",
        action: "post-message",
        dataCategories: [],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
      },
    });
    const pulled = await app.inject({
      method: "GET",
      url: `/records?agentId=${encodeURIComponent(agentDid)}`,
    });
    const { records } = pulled.json() as { records: readonly string[] };

    const otherDid = await other.inject({ method: "GET", url: "/.well-known/did.json" });
    const otherPublicKey = publicKeyFrom(otherDid.json() as DidWebDocument);

    const verified = verifyAuditRecord({ record: records[0]!, publicKey: otherPublicKey });
    expect(verified.ok).toBe(false);
    if (!verified.ok) expect(verified.error.code).toBe("SIGNATURE_INVALID");
  });

  // Regression test for a bug found by manually smoke-testing the real
  // built services: this service's signing key is ephemeral (regenerated on
  // every process start, same as vault's and revocation's own signing
  // identities). Storing a pre-signed envelope meant every record signed by
  // a since-restarted process permanently failed to verify. Records are now
  // signed fresh on every read (see the doc comment on `auditRecords` in
  // ./db/schema.js) — this proves a "restart" (a fresh server instance
  // against the same rows, with a new key) does not orphan history.
  it("still verifies a pre-existing record after a simulated restart with a new signing key", async () => {
    const domain = "127.0.0.1:4829";
    const before = await buildServer({ db, didDomain: domain });
    const agentDid = `did:web:${encodeURIComponent(domain)}:agents:${randomUUID()}`;

    await before.inject({
      method: "POST",
      url: "/records",
      payload: {
        agentDid,
        tool: "mock-slack",
        action: "post-message",
        dataCategories: [],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
      },
    });

    // A fresh buildServer() call, same domain, generates a brand-new
    // keypair — exactly what happens on a real process restart.
    const after = await buildServer({ db, didDomain: domain });
    const pulled = await after.inject({
      method: "GET",
      url: `/records?agentId=${encodeURIComponent(agentDid)}`,
    });
    const { records } = pulled.json() as { records: readonly string[] };
    expect(records).toHaveLength(1);

    const didResponse = await after.inject({ method: "GET", url: "/.well-known/did.json" });
    const publicKey = publicKeyFrom(didResponse.json() as DidWebDocument);
    const verified = verifyAuditRecord({ record: records[0]!, publicKey });
    expect(verified.ok).toBe(true);
  });

  it("pulls every record for one agent via GET /records?agentId=", async () => {
    const app = await buildServer({ db, didDomain: "127.0.0.1:4827" });
    // Randomized rather than port-derived: Postgres persists across test
    // runs (see services/revocation's own tests for the same lesson), so a
    // fixed DID here would accumulate records from earlier runs and break
    // the exact-count assertion below.
    const agentDid = `did:web:127.0.0.1%3A4827:agents:only-this-one-${randomUUID()}`;
    const otherAgentDid = `did:web:127.0.0.1%3A4827:agents:someone-else-${randomUUID()}`;

    await app.inject({
      method: "POST",
      url: "/records",
      payload: {
        agentDid,
        tool: "mock-slack",
        action: "post-message",
        dataCategories: [],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
      },
    });
    await app.inject({
      method: "POST",
      url: "/records",
      payload: {
        agentDid,
        tool: "stripe",
        action: "list-customers",
        dataCategories: [],
        policy: { rule: "agent-tool-allowlist", decision: "deny" },
        reason: "no policy grant for this agent/tool pair",
      },
    });
    await app.inject({
      method: "POST",
      url: "/records",
      payload: {
        agentDid: otherAgentDid,
        tool: "mock-slack",
        action: "post-message",
        dataCategories: [],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
      },
    });

    const response = await app.inject({
      method: "GET",
      url: `/records?agentId=${encodeURIComponent(agentDid)}`,
    });
    expect(response.statusCode).toBe(200);
    const { records } = response.json() as { records: readonly string[] };
    expect(records).toHaveLength(2);

    const didResponse = await app.inject({ method: "GET", url: "/.well-known/did.json" });
    const publicKey = publicKeyFrom(didResponse.json() as DidWebDocument);
    for (const record of records) {
      const verified = verifyAuditRecord({ record, publicKey });
      expect(verified.ok).toBe(true);
      if (verified.ok) expect(verified.value.agentDid).toBe(agentDid);
    }
  });

  it("returns every record when no agentId filter is given", async () => {
    const app = await buildServer({ db, didDomain: "127.0.0.1:4828" });
    await app.inject({
      method: "POST",
      url: "/records",
      payload: {
        agentDid: "did:web:127.0.0.1%3A4828:agents:a1",
        tool: "mock-slack",
        action: "post-message",
        dataCategories: [],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
      },
    });

    const response = await app.inject({ method: "GET", url: "/records" });
    expect(response.statusCode).toBe(200);
    const { records } = response.json() as { records: readonly string[] };
    expect(records.length).toBeGreaterThanOrEqual(1);
  });
});

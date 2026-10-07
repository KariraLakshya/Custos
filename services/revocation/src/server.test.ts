import { randomUUID } from "node:crypto";
import {
  decodeStatusList,
  isRevoked,
  verifyCredential,
  verifyRevocationTombstone,
  type DidWebDocument,
  type SignedCredential,
} from "@custos/core";
import { fixedClock } from "@custos/testing";
import type { AuditEvent, AuditReporter } from "@custos/audit-client";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb } from "./db/client.js";
import { buildServer } from "./server.js";
import type { BroadcastOutcome, TombstoneBroadcaster } from "./broadcast.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);

const controlPlane = createTestControlPlane(db);
let serviceKey: string;
let operatorKey: string;

beforeAll(async () => {
  serviceKey = await controlPlane.key("service", ["status:allocate"]);
  operatorKey = await controlPlane.key("operator", ["agents:revoke"]);
});

afterAll(async () => {
  await db.$client.end();
});

function recordingBroadcaster(): TombstoneBroadcaster & { readonly sent: readonly string[] } {
  const sent: string[] = [];
  return {
    get sent() {
      return sent;
    },
    async broadcast(tombstone: string): Promise<BroadcastOutcome> {
      sent.push(tombstone);
      return { delivered: 1, failed: [] };
    },
  };
}

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
  return Uint8Array.from(bytes.reverse());
}

async function buildTestServer(broadcaster?: TombstoneBroadcaster, auditReporter?: AuditReporter) {
  return buildServer({
    db,
    auditReporter: auditReporter ?? { report: () => {} },
    controlPlaneAuth: controlPlane.guard,
    didDomain: "127.0.0.1:4503",
    clock: fixedClock("2026-09-07T10:00:00.000Z"),
    ...(broadcaster ? { broadcaster } : {}),
  });
}

async function allocate(
  app: Awaited<ReturnType<typeof buildTestServer>>,
  agentId: string,
): Promise<number> {
  const response = await app.inject({
    method: "POST",
    url: "/agents",
    headers: bearer(serviceKey),
    payload: { agentId, agentDid: `did:web:127.0.0.1%3A4501:agents:${agentId}` },
  });
  expect(response.statusCode).toBe(201);
  return (response.json() as { statusListIndex: number }).statusListIndex;
}

describe("revocation service", () => {
  it("responds to /health", async () => {
    const app = await buildTestServer();
    const response = await app.inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "revocation" });
  });

  it("publishes the did:web document subscribers verify tombstones against", async () => {
    const app = await buildTestServer();
    const response = await app.inject({ method: "GET", url: "/.well-known/did.json" });
    expect(response.statusCode).toBe(200);
    const didDocument = response.json() as DidWebDocument;
    expect(didDocument.id).toBe("did:web:127.0.0.1%3A4503");
    expect(didDocument.verificationMethod[0].type).toBe("Ed25519VerificationKey2020");
    expect(didDocument.assertionMethod).toHaveLength(1);
  });

  describe("index allocation", () => {
    it("allocates a status list index for a new agent", async () => {
      const app = await buildTestServer();
      const agentId = randomUUID();
      const response = await app.inject({
        method: "POST",
        url: "/agents",
        headers: bearer(serviceKey),
        payload: { agentId, agentDid: `did:web:127.0.0.1%3A4501:agents:${agentId}` },
      });
      expect(response.statusCode).toBe(201);
      const body = response.json() as {
        statusListIndex: number;
        statusListCredential: string;
        agentDid: string;
      };
      expect(Number.isInteger(body.statusListIndex)).toBe(true);
      expect(body.statusListIndex).toBeGreaterThanOrEqual(0);
      expect(body.statusListCredential).toBe("http://127.0.0.1:4503/status/revocation");
    });

    it("gives different agents different indexes", async () => {
      const app = await buildTestServer();
      const first = await allocate(app, randomUUID());
      const second = await allocate(app, randomUUID());
      expect(first).not.toBe(second);
    });

    it("is idempotent — a retried registration reuses the same index", async () => {
      const app = await buildTestServer();
      const agentId = randomUUID();
      const first = await allocate(app, agentId);
      const second = await allocate(app, agentId);
      expect(second).toBe(first);
    });

    it("rejects a malformed allocation request", async () => {
      const app = await buildTestServer();
      const response = await app.inject({
        method: "POST",
        url: "/agents",
        headers: bearer(serviceKey),
        payload: { agentId: "not-a-uuid", agentDid: "did:web:example" },
      });
      expect(response.statusCode).toBe(400);
    });
  });

  describe("revocation", () => {
    it("revokes an agent and broadcasts a tombstone that verifies", async () => {
      const broadcaster = recordingBroadcaster();
      const app = await buildTestServer(broadcaster);
      const agentId = randomUUID();
      const statusListIndex = await allocate(app, agentId);

      const response = await app.inject({
        method: "POST",
        url: "/revocations",
        headers: bearer(operatorKey),
        payload: { agentId, reason: "suspected compromise" },
      });
      expect(response.statusCode).toBe(200);
      const body = response.json() as {
        agentDid: string;
        statusListIndex: number;
        revokedAt: string;
        alreadyRevoked: boolean;
        broadcast: BroadcastOutcome;
      };
      expect(body.statusListIndex).toBe(statusListIndex);
      expect(body.alreadyRevoked).toBe(false);
      expect(body.broadcast.delivered).toBe(1);

      expect(broadcaster.sent).toHaveLength(1);
      const didResponse = await app.inject({ method: "GET", url: "/.well-known/did.json" });
      const verified = verifyRevocationTombstone({
        tombstone: broadcaster.sent[0]!,
        publicKey: publicKeyFrom(didResponse.json() as DidWebDocument),
      });
      expect(verified.ok).toBe(true);
      if (verified.ok) {
        expect(verified.value.agentDid).toBe(body.agentDid);
        expect(verified.value.statusListIndex).toBe(statusListIndex);
        expect(verified.value.reason).toBe("suspected compromise");
      }
    });

    it("rejects revoking an agent it has never heard of", async () => {
      const app = await buildTestServer();
      const response = await app.inject({
        method: "POST",
        url: "/revocations",
        headers: bearer(operatorKey),
        payload: { agentId: randomUUID() },
      });
      expect(response.statusCode).toBe(404);
      expect((response.json() as { error: { code: string } }).error.code).toBe("UNKNOWN_AGENT");
    });

    it("rejects a malformed revocation request", async () => {
      const app = await buildTestServer();
      const response = await app.inject({
        method: "POST",
        url: "/revocations",
        headers: bearer(operatorKey),
        payload: { agentId: "not-a-uuid" },
      });
      expect(response.statusCode).toBe(400);
    });

    // An operator re-running deprovision must not rewrite when access was
    // actually withdrawn, but must be able to force redelivery.
    it("is idempotent: re-revoking keeps the original timestamp but re-broadcasts", async () => {
      const broadcaster = recordingBroadcaster();
      const app = await buildTestServer(broadcaster);
      const agentId = randomUUID();
      await allocate(app, agentId);

      const first = await app.inject({
        method: "POST",
        url: "/revocations",
        headers: bearer(operatorKey),
        payload: { agentId },
      });
      const second = await app.inject({
        method: "POST",
        url: "/revocations",
        headers: bearer(operatorKey),
        payload: { agentId },
      });

      const firstBody = first.json() as { revokedAt: string; alreadyRevoked: boolean };
      const secondBody = second.json() as { revokedAt: string; alreadyRevoked: boolean };
      expect(firstBody.alreadyRevoked).toBe(false);
      expect(secondBody.alreadyRevoked).toBe(true);
      expect(secondBody.revokedAt).toBe(firstBody.revokedAt);
      expect(broadcaster.sent).toHaveLength(2);
    });
  });

  describe("resync", () => {
    it("replays every revocation as a verifiable tombstone", async () => {
      const app = await buildTestServer();
      const agentId = randomUUID();
      await allocate(app, agentId);
      await app.inject({
        method: "POST",
        url: "/revocations",
        headers: bearer(operatorKey),
        payload: { agentId },
      });

      const response = await app.inject({ method: "GET", url: "/revocations" });
      expect(response.statusCode).toBe(200);
      const body = response.json() as { tombstones: string[]; asOf: string };
      expect(body.asOf).toBe("2026-09-07T10:00:00.000Z");

      const didResponse = await app.inject({ method: "GET", url: "/.well-known/did.json" });
      const publicKey = publicKeyFrom(didResponse.json() as DidWebDocument);
      const dids = body.tombstones.map((tombstone) => {
        const verified = verifyRevocationTombstone({ tombstone, publicKey });
        expect(verified.ok).toBe(true);
        return verified.ok ? verified.value.agentDid : "";
      });
      expect(dids).toContain(`did:web:127.0.0.1%3A4501:agents:${agentId}`);
    });
  });

  describe("published status list credential", () => {
    it("is independently verifiable and records exactly who was revoked", async () => {
      const app = await buildTestServer();
      const revokedId = randomUUID();
      const activeId = randomUUID();
      const revokedIndex = await allocate(app, revokedId);
      const activeIndex = await allocate(app, activeId);
      await app.inject({
        method: "POST",
        url: "/revocations",
        headers: bearer(operatorKey),
        payload: { agentId: revokedId },
      });

      const response = await app.inject({ method: "GET", url: "/status/revocation" });
      expect(response.statusCode).toBe(200);
      const credential = response.json() as SignedCredential;
      expect(credential.type).toContain("BitstringStatusListCredential");

      // Verified against the service's published DID document alone — the
      // same path a third party with no access to our database would take.
      const didResponse = await app.inject({ method: "GET", url: "/.well-known/did.json" });
      const verified = await verifyCredential({
        credential,
        didDocument: didResponse.json() as DidWebDocument,
      });
      expect(verified.ok).toBe(true);

      const subject = credential.credentialSubject as { encodedList: string; type: string };
      expect(subject.type).toBe("BitstringStatusList");
      const decoded = decodeStatusList(subject.encodedList);
      expect(decoded.ok).toBe(true);
      if (!decoded.ok) return;
      const revokedBit = isRevoked(decoded.value, revokedIndex);
      const activeBit = isRevoked(decoded.value, activeIndex);
      expect(revokedBit.ok && revokedBit.value).toBe(true);
      expect(activeBit.ok && activeBit.value).toBe(false);
    });

    it("publishes an explicit staleness bound when configured", async () => {
      const app = await buildServer({
        db,
        auditReporter: { report: () => {} },
        controlPlaneAuth: controlPlane.guard,
        didDomain: "127.0.0.1:4503",
        statusTtlMs: 30_000,
        clock: fixedClock("2026-09-07T10:00:00.000Z"),
      });
      const response = await app.inject({ method: "GET", url: "/status/revocation" });
      const credential = response.json() as SignedCredential;
      expect((credential.credentialSubject as { ttl: number }).ttl).toBe(30_000);
    });
  });
});

describe("revocation control-plane authentication (ADR 0008)", () => {
  const UNAUTHORIZED = { error: { code: "UNAUTHORIZED" } };

  it("refuses to allocate a status slot without a status:allocate service key", async () => {
    const app = await buildTestServer();
    const keys = [
      undefined,
      await controlPlane.key("operator", ["agents:revoke", "agents:register"]),
      await controlPlane.key("service", ["audit:write"]),
      await controlPlane.key("service", ["status:allocate"], {
        expiresAt: new Date("2020-01-01T00:00:00Z"),
      }),
    ];
    for (const key of keys) {
      const agentId = randomUUID();
      const response = await app.inject({
        method: "POST",
        url: "/agents",
        ...(key ? { headers: bearer(key) } : {}),
        payload: { agentId, agentDid: `did:web:127.0.0.1%3A4501:agents:${agentId}` },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual(UNAUTHORIZED);
    }
  });

  it("refuses to revoke without an agents:revoke operator key, broadcasting nothing", async () => {
    const broadcaster = recordingBroadcaster();
    const app = await buildTestServer(broadcaster);
    const agentId = randomUUID();
    await allocate(app, agentId);
    const keys = [
      undefined,
      await controlPlane.key("operator", ["policies:write"]),
      await controlPlane.key("operator", ["agents:revoke"], {
        expiresAt: new Date("2020-01-01T00:00:00Z"),
      }),
    ];
    for (const key of keys) {
      const response = await app.inject({
        method: "POST",
        url: "/revocations",
        ...(key ? { headers: bearer(key) } : {}),
        payload: { agentId },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual(UNAUTHORIZED);
    }
    expect(broadcaster.sent).toEqual([]);
    // Tombstones are encoded, so decode them rather than search the raw text.
    const status = await app.inject({ method: "GET", url: "/revocations" });
    const didResponse = await app.inject({ method: "GET", url: "/.well-known/did.json" });
    const publicKey = publicKeyFrom(didResponse.json() as DidWebDocument);
    const revokedDids = (status.json() as { tombstones: string[] }).tombstones.map((tombstone) => {
      const verified = verifyRevocationTombstone({ tombstone, publicKey });
      return verified.ok ? verified.value.agentDid : "unverifiable";
    });
    expect(revokedDids.some((did) => did.endsWith(agentId))).toBe(false);
    expect(revokedDids).not.toContain("unverifiable");
  });
});

describe("revocation control-plane auditing (ADR 0008 §7)", () => {
  it("audits an allocation and a revocation with their callers, and a scope denial", async () => {
    const events: AuditEvent[] = [];
    const app = await buildTestServer(undefined, { report: (event) => events.push(event) });
    const agentId = randomUUID();
    await allocate(app, agentId);
    const agentDid = `did:web:127.0.0.1%3A4501:agents:${agentId}`;

    const policiesOnly = await controlPlane.key("operator", ["policies:write"]);
    await app.inject({
      method: "POST",
      url: "/revocations",
      headers: bearer(policiesOnly),
      payload: { agentId },
    });
    // Unauthenticated: logged, never audited.
    await app.inject({ method: "POST", url: "/revocations", payload: { agentId } });
    const revoked = await app.inject({
      method: "POST",
      url: "/revocations",
      headers: bearer(operatorKey),
      payload: { agentId, reason: "compromised" },
    });
    expect(revoked.statusCode).toBe(200);

    expect(events).toEqual([
      {
        principal: { kind: "service", id: serviceKey.split("_")[2], name: "test-service" },
        action: "status.allocate",
        dataCategories: [],
        policy: { rule: "control-plane-scope:status:allocate", decision: "allow" },
        agentDid,
      },
      {
        principal: { kind: "operator", id: policiesOnly.split("_")[2], name: "test-operator" },
        action: "agents.revoke",
        dataCategories: [],
        policy: { rule: "control-plane-scope:agents:revoke", decision: "deny" },
      },
      {
        principal: { kind: "operator", id: operatorKey.split("_")[2], name: "test-operator" },
        action: "agents.revoke",
        dataCategories: [],
        policy: { rule: "control-plane-scope:agents:revoke", decision: "allow" },
        agentDid,
        reason: "compromised",
      },
    ]);
  });

  it("refuses to build without a service key when no audit reporter is injected", async () => {
    await expect(buildServer({ db, controlPlaneAuth: controlPlane.guard })).rejects.toThrow(
      "serviceKey or mtlsFetch is required when auditReporter is not injected",
    );
  });
});

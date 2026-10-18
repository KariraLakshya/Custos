import { createServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import {
  buildDidWebDocument,
  createStatusList,
  generateKeyPair,
  isRevoked,
  issueStatusListCredential,
  decodeStatusList,
  setRevoked,
  type SignedCredential,
} from "@custos/core";
import type { AuditEvent } from "@custos/audit-client";
import { err } from "@custos/contracts";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { BroadcastOutcome, TombstoneBroadcaster } from "../broadcast.js";
import { createDb } from "../db/client.js";
import { externalRevokedIndexes, statusListEntries } from "../db/schema.js";
import { createSigningKey } from "../keys/signing-key.js";
import { buildServer } from "../server.js";
import {
  createHttpListFetcher,
  createPublishedListReconciler,
  PUBLISHED_LIST_REASON,
} from "./reconcile.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);
const controlPlane = createTestControlPlane(db);

const DOMAIN = "127.0.0.1:4531";
const ISSUER_DID = "did:web:127.0.0.1%3A4531";
const LIST_URL = "http://127.0.0.1:4531/status/revocation";
const WINDOW_SECONDS = 600;
const T0 = new Date("2026-10-18T10:00:00.000Z");
// Far above anything a serial allocates in a test run, so these never collide with real agents.
const UNKNOWN_BASE = 900_000;

let serviceKey: string;
let operatorKey: string;
beforeAll(async () => {
  serviceKey = await controlPlane.key("service", ["status:allocate"]);
  operatorKey = await controlPlane.key("operator", ["agents:revoke"]);
});
afterEach(async () => {
  await db.delete(externalRevokedIndexes);
});
afterAll(async () => {
  await db.delete(externalRevokedIndexes);
  await db.$client.end();
});

const signingKey = () =>
  createSigningKey({ REVOCATION_SIGNING_SEED: Buffer.alloc(32, 9).toString("hex") });

/** A signed published list, as the publisher would post it. */
async function publish(
  revoked: readonly number[],
  options: {
    validFrom?: Date;
    validUntil?: Date | null;
    keys?: ReturnType<typeof signingKey>;
    url?: string;
  } = {},
): Promise<SignedCredential> {
  const { keyProvider, keyId } = options.keys ?? signingKey();
  let list = createStatusList(Math.max(0, ...revoked) + 1);
  for (const index of revoked) {
    const next = setRevoked(list, index, true);
    if (!next.ok) throw new Error("fixture");
    list = next.value;
  }
  const didDocument = buildDidWebDocument({
    domain: DOMAIN,
    publicKey: await keyProvider.getPublicKey(keyId),
  });
  const validFrom = options.validFrom ?? T0;
  const issued = await issueStatusListCredential({
    list,
    issuerDid: ISSUER_DID,
    signer: {
      id: didDocument.verificationMethod[0].id,
      sign: (input) => keyProvider.sign(keyId, input.data),
    },
    statusListCredentialUrl: options.url ?? LIST_URL,
    now: validFrom,
    ...(options.validUntil === null
      ? {}
      : {
          validUntil: options.validUntil ?? new Date(validFrom.getTime() + WINDOW_SECONDS * 1000),
        }),
  });
  if (!issued.ok) throw new Error(issued.error.reason);
  return issued.value;
}

function recordingBroadcaster(): TombstoneBroadcaster & { readonly sent: string[] } {
  const sent: string[] = [];
  return {
    sent,
    async broadcast(tombstone): Promise<BroadcastOutcome> {
      sent.push(tombstone);
      return { delivered: 1, failed: [] };
    },
  };
}

async function harness(initial: unknown = undefined) {
  let current: unknown = initial;
  let now = T0;
  const broadcaster = recordingBroadcaster();
  const events: AuditEvent[] = [];
  const app = await buildServer({
    db,
    signingKey: signingKey(),
    auditReporter: { report: (event) => void events.push(event) },
    controlPlaneAuth: controlPlane.guard,
    didDomain: DOMAIN,
    clock: { now: () => now },
    broadcaster,
    publishedList: {
      maxAgeSeconds: WINDOW_SECONDS,
      maxClockSkewSeconds: 5,
      fetchList: async () => {
        if (current instanceof Error) throw current;
        return current;
      },
    },
  });
  const reconciler = app.publishedList!;
  return {
    app,
    reconciler,
    broadcaster,
    events,
    serve: (value: unknown) => {
      current = value;
    },
    setNow: (value: Date) => {
      now = value;
    },
    reconcile: () => reconciler.reconcileOnce(now),
  };
}

async function allocate(app: Awaited<ReturnType<typeof harness>>["app"]) {
  const agentId = randomUUID();
  const response = await app.inject({
    method: "POST",
    url: "/agents",
    headers: bearer(serviceKey),
    payload: { agentId, agentDid: `did:web:a.example:agents:${agentId}` },
  });
  expect(response.statusCode).toBe(201);
  return { agentId, index: (response.json() as { statusListIndex: number }).statusListIndex };
}

async function rowOf(agentId: string) {
  const rows = await db
    .select()
    .from(statusListEntries)
    .where(eq(statusListEntries.agentId, agentId));
  return rows[0]!;
}

const body = (response: { json: () => unknown }) => response.json() as Record<string, unknown>;

describe("published list: the gate", () => {
  it("answers 503 on the two reads until a list has been verified, while writes keep working", async () => {
    const h = await harness();
    expect((await h.app.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(503);
    const tombstones = await h.app.inject({ method: "GET", url: "/revocations" });
    expect(tombstones.statusCode).toBe(503);
    expect(body(tombstones)).toEqual({ error: "PUBLISHED_STATE_UNKNOWN" });
    expect(tombstones.headers["access-control-allow-origin"]).toBe("*");

    const health = await h.app.inject({ method: "GET", url: "/health" });
    expect(health.statusCode).toBe(200);
    expect(body(health).published).toEqual({ open: false, confirmedUntil: null });

    // Allocating and revoking are the emergency path and are never held back.
    const { agentId } = await allocate(h.app);
    const revoked = await h.app.inject({
      method: "POST",
      url: "/revocations",
      headers: bearer(operatorKey),
      payload: { agentId },
    });
    expect(revoked.statusCode).toBe(200);
  });

  it("opens after a verified list, closes again when its window ends, and reopens on the next one", async () => {
    const h = await harness(await publish([]));
    expect((await h.reconcile()).ok).toBe(true);
    expect((await h.app.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(200);
    expect((await h.app.inject({ method: "GET", url: "/revocations" })).statusCode).toBe(200);
    expect(body(await h.app.inject({ method: "GET", url: "/health" })).published).toEqual({
      open: true,
      confirmedUntil: "2026-10-18T10:10:00.000Z",
    });

    h.setNow(new Date(T0.getTime() + WINDOW_SECONDS * 1000)); // the boundary is exclusive
    expect((await h.app.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(503);

    const later = new Date(T0.getTime() + 700_000);
    h.setNow(later);
    h.serve(await publish([], { validFrom: new Date(later.getTime() - 5_000) }));
    expect((await h.reconcile()).ok).toBe(true);
    expect((await h.app.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(200);
  });

  it("leaves a deployment that does not turn the feature on exactly as it was", async () => {
    const app = await buildServer({
      db,
      signingKey: signingKey(),
      auditReporter: { report: () => {} },
      controlPlaneAuth: controlPlane.guard,
      didDomain: DOMAIN,
      clock: { now: () => T0 },
    });
    expect(app.publishedList).toBeUndefined();
    expect((await app.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: "/revocations" })).statusCode).toBe(200);
    expect(body(await app.inject({ method: "GET", url: "/health" }))).toEqual({
      status: "ok",
      service: "revocation",
    });
  });
});

describe("published list: the merge", () => {
  it("revokes a known agent, pushes its tombstone once, audits it, and serves the bit", async () => {
    const h = await harness();
    const { agentId, index } = await allocate(h.app);
    h.serve(await publish([index]));

    const result = await h.reconcile();
    expect(result).toMatchObject({
      ok: true,
      value: { revokedAgents: 1, storedByIndex: 0, confirmed: true },
    });

    const row = await rowOf(agentId);
    expect(row.revokedAt).not.toBeNull();
    expect(row.reason).toBe(PUBLISHED_LIST_REASON);
    expect(h.broadcaster.sent).toHaveLength(1);

    const audited = h.events.filter((event) => event.reason === PUBLISHED_LIST_REASON);
    expect(audited).toHaveLength(1);
    expect(audited[0]).toMatchObject({
      principal: { kind: "service", id: "revocation-reconciler" },
      action: "agents.revoke",
      agentDid: `did:web:a.example:agents:${agentId}`,
      policy: { decision: "allow" },
    });

    const served = (await h.app.inject({ method: "GET", url: "/status/revocation" })).json() as {
      credentialSubject: { encodedList: string };
    };
    const decoded = decodeStatusList(served.credentialSubject.encodedList);
    if (!decoded.ok) throw new Error("fixture");
    expect(isRevoked(decoded.value, index)).toEqual({ ok: true, value: true });
  });

  it("does nothing the second time: no new write, no re-push, no new audit event", async () => {
    const h = await harness();
    const { index } = await allocate(h.app);
    h.serve(await publish([index, UNKNOWN_BASE + 1]));
    expect((await h.reconcile()).ok).toBe(true);
    const sent = h.broadcaster.sent.length;
    const audited = h.events.length;

    const again = await h.reconcile();
    expect(again).toMatchObject({ ok: true, value: { revokedAgents: 0, storedByIndex: 0 } });
    expect(h.broadcaster.sent).toHaveLength(sent);
    expect(h.events).toHaveLength(audited);
  });

  it("does not touch an agent that was already revoked here, and keeps the original time", async () => {
    const h = await harness();
    const { agentId, index } = await allocate(h.app);
    await h.app.inject({
      method: "POST",
      url: "/revocations",
      headers: bearer(operatorKey),
      payload: { agentId, reason: "by-hand" },
    });
    const before = await rowOf(agentId);
    const sent = h.broadcaster.sent.length;

    h.serve(await publish([index]));
    expect(await h.reconcile()).toMatchObject({ ok: true, value: { revokedAgents: 0 } });
    expect(await rowOf(agentId)).toEqual(before);
    expect(h.broadcaster.sent).toHaveLength(sent);
  });

  it("keeps a bit by index when this database has no row for it, and serves it", async () => {
    const h = await harness();
    const unknown = UNKNOWN_BASE + 7;
    h.serve(await publish([unknown]));

    expect(await h.reconcile()).toMatchObject({
      ok: true,
      value: { storedByIndex: 1, revokedAgents: 0 },
    });
    const rows = await db.select().from(externalRevokedIndexes);
    expect(rows.map((row) => row.statusListIndex)).toContain(unknown);
    expect(h.events.find((event) => event.agentDid === undefined)).toMatchObject({
      principal: { kind: "service" },
      reason: `${PUBLISHED_LIST_REASON}: status list index ${unknown}`,
    });

    const served = (await h.app.inject({ method: "GET", url: "/status/revocation" })).json() as {
      credentialSubject: { encodedList: string };
    };
    const decoded = decodeStatusList(served.credentialSubject.encodedList);
    if (!decoded.ok) throw new Error("fixture");
    expect(isRevoked(decoded.value, unknown)).toEqual({ ok: true, value: true });
  });

  it("never clears a bit: a later list without it changes nothing here", async () => {
    const h = await harness();
    const { agentId, index } = await allocate(h.app);
    h.serve(await publish([index, UNKNOWN_BASE + 3]));
    await h.reconcile();

    h.serve(await publish([]));
    expect((await h.reconcile()).ok).toBe(true);
    expect((await rowOf(agentId)).revokedAt).not.toBeNull();
    const rows = await db.select().from(externalRevokedIndexes);
    expect(rows.map((row) => row.statusListIndex)).toContain(UNKNOWN_BASE + 3);
  });

  it("merges a large list in batches", async () => {
    const h = await harness();
    const many = Array.from({ length: 1_500 }, (_, i) => UNKNOWN_BASE + 100 + i);
    h.serve(await publish(many));
    expect(await h.reconcile()).toMatchObject({ ok: true, value: { storedByIndex: 1_500 } });
    expect(await h.reconcile()).toMatchObject({ ok: true, value: { storedByIndex: 0 } });
  });

  it("merges the bits of a correctly signed list that is past its window, without reopening the gate", async () => {
    const h = await harness();
    const { agentId, index } = await allocate(h.app);
    const later = new Date(T0.getTime() + 3_600_000);
    h.setNow(later);
    h.serve(await publish([index], { validFrom: T0 })); // an hour old, window ten minutes

    expect(await h.reconcile()).toMatchObject({
      ok: true,
      value: { revokedAgents: 1, confirmed: false },
    });
    expect((await rowOf(agentId)).revokedAt).not.toBeNull();
    expect(h.reconciler.isOpen(later)).toBe(false);
    expect((await h.app.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(503);
  });
});

describe("published list: what is refused", () => {
  async function expectRefused(
    h: Awaited<ReturnType<typeof harness>>,
    input: unknown,
    code: string,
  ) {
    const { agentId, index } = await allocate(h.app);
    void index;
    h.serve(input);
    const result = await h.reconcile();
    expect(result).toMatchObject({ ok: false, error: { code } });
    expect((await rowOf(agentId)).revokedAt).toBeNull();
    expect((await db.select().from(externalRevokedIndexes)).length).toBe(0);
    expect(h.reconciler.isOpen(T0)).toBe(false);
    expect((await h.app.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(503);
  }

  it("a list signed by someone else's key, even one carrying this service's did", async () => {
    const h = await harness();
    const { index } = await allocate(h.app);
    const other = createSigningKey({
      REVOCATION_SIGNING_SEED: Buffer.alloc(32, 3).toString("hex"),
    });
    await expectRefused(h, await publish([index], { keys: other }), "LIST_REJECTED");
  });

  it("a list with another identity, a tampered list, a list without validUntil, and a future one", async () => {
    const h = await harness();
    const { index } = await allocate(h.app);
    await expectRefused(
      h,
      await publish([index], { url: "https://evil.example/list" }),
      "LIST_REJECTED",
    );

    const tampered = structuredClone(await publish([])) as unknown as {
      credentialSubject: { encodedList: string };
    };
    const real = await publish([index]);
    tampered.credentialSubject.encodedList = (
      real as unknown as { credentialSubject: { encodedList: string } }
    ).credentialSubject.encodedList;
    await expectRefused(h, tampered, "LIST_REJECTED");

    await expectRefused(h, await publish([index], { validUntil: null }), "LIST_REJECTED");
    await expectRefused(
      h,
      await publish([index], { validFrom: new Date(T0.getTime() + 60_000) }),
      "LIST_REJECTED",
    );
  });

  it("a host that is down, that answers with nonsense, or that answers with the wrong shape", async () => {
    const h = await harness();
    await expectRefused(h, new Error("connect ECONNREFUSED"), "FETCH_FAILED");
    await expectRefused(h, "not a credential", "LIST_REJECTED");
    await expectRefused(h, null, "LIST_REJECTED");
    await expectRefused(h, { issuer: ISSUER_DID }, "LIST_REJECTED");
  });

  it("applies nothing and keeps the gate shut when a revocation cannot be applied", async () => {
    const reconciler = createPublishedListReconciler({
      db,
      anchor: {
        statusIssuerDid: ISSUER_DID,
        statusIssuerPublicKey: await signingKey().keyProvider.getPublicKey(signingKey().keyId),
        statusListId: LIST_URL,
        maxStatusAgeSeconds: WINDOW_SECONDS,
      },
      fetchList: async () => publishFor(),
      maxClockSkewSeconds: 5,
      revoke: async () => err({ code: "SIGNING_FAILED" as const, reason: "kms unreachable" }),
      report: () => {},
    });
    const probe = await harness();
    const { index } = await allocate(probe.app);
    async function publishFor() {
      return publish([index]);
    }
    expect(await reconciler.reconcileOnce(T0)).toMatchObject({
      ok: false,
      error: { code: "MERGE_INCOMPLETE", failed: 1 },
    });
    expect(reconciler.isOpen(T0)).toBe(false);
  });

  it("does not run two merges at once", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const reconciler = createPublishedListReconciler({
      db,
      anchor: {
        statusIssuerDid: ISSUER_DID,
        statusIssuerPublicKey: await signingKey().keyProvider.getPublicKey(signingKey().keyId),
        statusListId: LIST_URL,
        maxStatusAgeSeconds: WINDOW_SECONDS,
      },
      fetchList: async () => {
        await gate;
        return publish([]);
      },
      maxClockSkewSeconds: 5,
      revoke: async () => err({ code: "SIGNING_FAILED" as const, reason: "unused" }),
      report: () => {},
    });
    const first = reconciler.reconcileOnce(T0);
    expect(await reconciler.reconcileOnce(T0)).toMatchObject({
      ok: false,
      error: { code: "ALREADY_RUNNING" },
    });
    release();
    expect((await first).ok).toBe(true);
  });
});

describe("published list: polling", () => {
  it("merges at start and again on every tick, and stops when told to", async () => {
    let calls = 0;
    const reconciler = createPublishedListReconciler({
      db,
      anchor: {
        statusIssuerDid: ISSUER_DID,
        statusIssuerPublicKey: generateKeyPair().publicKey,
        statusListId: LIST_URL,
        maxStatusAgeSeconds: WINDOW_SECONDS,
      },
      fetchList: async () => {
        calls += 1;
        throw new Error("down");
      },
      maxClockSkewSeconds: 5,
      revoke: async () => err({ code: "SIGNING_FAILED" as const, reason: "unused" }),
      report: () => {},
    });
    const errors: string[] = [];
    reconciler.start(
      20,
      () => T0,
      (error) => errors.push(error.code),
    );
    reconciler.start(
      20,
      () => T0,
      () => {},
    ); // a second start is ignored
    await new Promise((resolve) => setTimeout(resolve, 120));
    reconciler.stop();
    const callsWhenStopped = calls;
    expect(callsWhenStopped).toBeGreaterThanOrEqual(3);
    expect(errors.every((code) => code === "FETCH_FAILED")).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(calls).toBe(callsWhenStopped);
  });

  it("starts from buildServer's ready hook and stops on close", async () => {
    let calls = 0;
    const app = await buildServer({
      db,
      signingKey: signingKey(),
      auditReporter: { report: () => {} },
      controlPlaneAuth: controlPlane.guard,
      didDomain: DOMAIN,
      publishedList: {
        maxAgeSeconds: WINDOW_SECONDS,
        maxClockSkewSeconds: 5,
        pollIntervalMs: 20,
        fetchList: async () => {
          calls += 1;
          throw new Error("down");
        },
      },
    });
    await app.ready();
    await new Promise((resolve) => setTimeout(resolve, 100));
    await app.close();
    const atClose = calls;
    expect(atClose).toBeGreaterThanOrEqual(2);
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(calls).toBe(atClose);
  });
});

describe("createHttpListFetcher", () => {
  let server: Server;
  let base: string;
  const routes = new Map<string, (res: import("node:http").ServerResponse) => void>();

  beforeAll(async () => {
    server = createServer(
      (req, res) => routes.get(req.url ?? "")?.(res) ?? res.writeHead(404).end(),
    );
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("no port");
    base = `http://127.0.0.1:${address.port}`;
  });
  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("returns the parsed JSON of a 200", async () => {
    routes.set("/ok", (res) => res.writeHead(200).end('{"a":1}'));
    expect(await createHttpListFetcher({ url: `${base}/ok`, timeoutMs: 2_000 })()).toEqual({
      a: 1,
    });
  });

  it("refuses a non-200, invalid JSON, a body that is too large, and a host that never answers", async () => {
    routes.set("/500", (res) => res.writeHead(500).end("x"));
    routes.set("/bad", (res) => res.writeHead(200).end("<html>"));
    routes.set("/huge", (res) => res.writeHead(200).end("x".repeat(2_200_000)));
    routes.set("/hang", () => {});
    await expect(createHttpListFetcher({ url: `${base}/500`, timeoutMs: 2_000 })()).rejects.toThrow(
      "HTTP 500",
    );
    await expect(
      createHttpListFetcher({ url: `${base}/bad`, timeoutMs: 2_000 })(),
    ).rejects.toThrow();
    await expect(
      createHttpListFetcher({ url: `${base}/huge`, timeoutMs: 2_000 })(),
    ).rejects.toThrow("too large");
    await expect(
      createHttpListFetcher({ url: `${base}/hang`, timeoutMs: 150 })(),
    ).rejects.toThrow();
  });
});

describe("published list: edge cases the merge must get right", () => {
  const reconcilerWith = async (
    revoke: Parameters<typeof createPublishedListReconciler>[0]["revoke"],
    reports: AuditEvent[],
  ) => {
    const probe = await harness();
    const { index } = await allocate(probe.app);
    return createPublishedListReconciler({
      db,
      anchor: {
        statusIssuerDid: ISSUER_DID,
        statusIssuerPublicKey: await signingKey().keyProvider.getPublicKey(signingKey().keyId),
        statusListId: LIST_URL,
        maxStatusAgeSeconds: WINDOW_SECONDS,
      },
      fetchList: async () => publish([index]),
      maxClockSkewSeconds: 5,
      revoke,
      report: (event) => void reports.push(event),
    });
  };

  it("neither counts nor audits a revocation that someone else made in the gap", async () => {
    const reports: AuditEvent[] = [];
    const reconciler = await reconcilerWith(
      async (agentId) => ({
        ok: true,
        value: {
          agentId,
          agentDid: "did:web:a.example:agents:x",
          statusListIndex: 1,
          revokedAt: T0.toISOString(),
          alreadyRevoked: true,
          broadcast: { delivered: 0, failed: [] },
        },
      }),
      reports,
    );
    expect(await reconciler.reconcileOnce(T0)).toMatchObject({
      ok: true,
      value: { revokedAgents: 0 },
    });
    expect(reports).toEqual([]);
  });

  it("keeps serving a bit that was merged while the feature was on, after it is switched off", async () => {
    const unknown = UNKNOWN_BASE + 55;
    await db
      .insert(externalRevokedIndexes)
      .values({ statusListIndex: unknown, firstSeenInListAt: T0 });
    const app = await buildServer({
      db,
      signingKey: signingKey(),
      auditReporter: { report: () => {} },
      controlPlaneAuth: controlPlane.guard,
      didDomain: DOMAIN,
      clock: { now: () => T0 },
    });
    expect(app.publishedList).toBeUndefined();
    const served = (await app.inject({ method: "GET", url: "/status/revocation" })).json() as {
      credentialSubject: { encodedList: string };
    };
    const decoded = decodeStatusList(served.credentialSubject.encodedList);
    if (!decoded.ok) throw new Error("fixture");
    expect(isRevoked(decoded.value, unknown)).toEqual({ ok: true, value: true });
  });
});

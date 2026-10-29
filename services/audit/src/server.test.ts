import { randomUUID } from "node:crypto";
import {
  multibaseToPublicKey,
  verifyAuditLedger,
  type AuditRecord,
  type DidWebDocument,
  type KeyProvider,
} from "@custos/core";
import { fixedClock } from "@custos/testing";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import {
  createMigratedTestDatabase,
  createSealStoreTestDatabase,
  dropTestDatabase,
} from "@custos/vitest-config/hermetic-db";
import { createPostgresSealStore, type SealStore } from "@custos/audit-client";
import { fakeS3 } from "@custos/audit-client/testing";
import { createS3SealStore } from "@custos/audit-client/s3";
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createDb, type AuditDb } from "./db/client.js";
import { auditRecords, auditSeals } from "./db/schema.js";
import { createSigningKey } from "./keys/signing-key.js";
import { buildServer } from "./server.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);

const controlPlane = createTestControlPlane(db);
let serviceKey: string;

beforeAll(async () => {
  serviceKey = await controlPlane.key("service", ["audit:write"]);
});

afterAll(async () => {
  await db.$client.end();
});

const seedHex = (fill: number): string => Buffer.alloc(32, fill).toString("hex");
const signingKey = (fill = 5) => createSigningKey({ AUDIT_SIGNING_SEED: seedHex(fill) });
type App = Awaited<ReturnType<typeof buildServer>>;

function build(
  options: Partial<Parameters<typeof buildServer>[0]> & { port?: number } = {},
): Promise<App> {
  const { port = 4824, ...rest } = options;
  return buildServer({
    db,
    controlPlaneAuth: controlPlane.guard,
    didDomain: `127.0.0.1:${port}`,
    signingKey: signingKey(),
    ...rest,
  });
}

const event = (agentDid: string, action = "post-message") => ({
  agentDid,
  tool: "mock-slack",
  action,
  dataCategories: ["message-content"],
  policy: { rule: "agent-tool-allowlist", decision: "allow" },
});

async function post(app: App, payload: unknown, key = serviceKey) {
  return app.inject({ method: "POST", url: "/records", headers: bearer(key), payload });
}

/** Pulls the ledger and verifies it as an auditor would: against the served seal and any held. */
async function pullVerified(
  app: App,
  options: { agentDid?: string; held?: string[]; trustedKeys?: string[] } = {},
) {
  const url =
    options.agentDid === undefined
      ? "/records"
      : `/records?agentId=${encodeURIComponent(options.agentDid)}`;
  const body = (await app.inject({ method: "GET", url })).json() as {
    entries: unknown[];
    seal: string | null;
  };
  const did = (
    await app.inject({ method: "GET", url: "/.well-known/did.json" })
  ).json() as DidWebDocument;
  const published = did.verificationMethod[0].publicKeyMultibase;
  return {
    body,
    result: verifyAuditLedger({
      entries: body.entries,
      seals: [...(body.seal === null ? [] : [body.seal]), ...(options.held ?? [])],
      trustedKeys: options.trustedKeys ?? [published],
      log: did.id,
    }),
  };
}

async function recordsOf(app: App, agentDid: string): Promise<AuditRecord[]> {
  const { result } = await pullVerified(app, { agentDid });
  if (!result.ok) throw new Error(`ledger failed verification: ${result.error.code}`);
  return result.value.records.map((entry) => entry.record).filter((r) => r.agentDid === agentDid);
}

const serviceKeyId = () => serviceKey.split("_")[2];

describe("audit service", () => {
  it("responds to /health", async () => {
    const response = await (await build()).inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "audit" });
  });

  it("publishes its own DID document with the configured key", async () => {
    const app = await build({ port: 4821 });
    const did = (
      await app.inject({ method: "GET", url: "/.well-known/did.json" })
    ).json() as DidWebDocument;
    expect(did.id).toBe("did:web:127.0.0.1%3A4821");
    const key = multibaseToPublicKey(did.verificationMethod[0].publicKeyMultibase);
    const expected = signingKey();
    expect(key.ok && key.value).toEqual(await expected.keyProvider.getPublicKey(expected.keyId));
  });

  it("400s a malformed report and an invalid policy.decision", async () => {
    const app = await build();
    expect((await post(app, { tool: "x" })).statusCode).toBe(400);
    expect(
      (await post(app, { ...event("did:web:x"), policy: { rule: "x", decision: "maybe" } }))
        .statusCode,
    ).toBe(400);
  });
});

describe("the ledger (ADR 0017)", () => {
  it("chains reported records, and an auditor verifies them against the seal", async () => {
    const app = await build({ clock: fixedClock("2026-10-27T10:00:00.000Z") });
    const agentDid = `did:web:127.0.0.1%3A4824:agents:${randomUUID()}`;
    expect((await post(app, event(agentDid, "first"))).statusCode).toBe(201);
    expect((await post(app, event(agentDid, "second"))).statusCode).toBe(201);
    const sealed = await app.auditLedger.sealOnce();
    expect(sealed.ok && typeof sealed.value).toBe("number");

    const { result } = await pullVerified(app);
    expect(result).toMatchObject({ ok: true, value: { unsealedCount: 0 } });
    expect(await recordsOf(app, agentDid)).toEqual([
      expect.objectContaining({ action: "first", authorityChain: [agentDid] }),
      expect.objectContaining({ action: "second", recordedAt: "2026-10-27T10:00:00.000Z" }),
    ]);
  });

  it("records the authenticated caller as the reporter, not anything the body claims", async () => {
    const app = await build();
    const agentDid = `did:web:127.0.0.1%3A4824:agents:${randomUUID()}`;
    await post(app, {
      ...event(agentDid),
      reportedBy: { kind: "operator", id: "ffffffffffffffff", name: "someone-else" },
    });
    const [record] = await recordsOf(app, agentDid);
    expect(record?.reportedBy).toEqual({
      kind: "service",
      id: serviceKeyId(),
      name: "test-service",
    });
  });

  it("serves another agent's entries as hashes only, and one agent's view still verifies", async () => {
    const app = await build();
    const mine = `did:web:127.0.0.1%3A4824:agents:${randomUUID()}`;
    const theirs = `did:web:127.0.0.1%3A4824:agents:${randomUUID()}`;
    await post(app, event(mine));
    await post(app, event(theirs));
    await app.auditLedger.sealOnce();

    const { body, result } = await pullVerified(app, { agentDid: mine });
    expect(result.ok).toBe(true);
    const payloads = body.entries
      .map((entry) => (entry as { payload?: string }).payload)
      .filter((payload): payload is string => payload !== undefined);
    expect(payloads.some((payload) => payload.includes(mine))).toBe(true);
    expect(payloads.some((payload) => payload.includes(theirs))).toBe(false);
  });

  it("seals only when the head has moved", async () => {
    const app = await build();
    await post(app, event(`did:web:x:agents:${randomUUID()}`));
    expect((await app.auditLedger.sealOnce()).ok).toBe(true);
    expect(await app.auditLedger.sealOnce()).toEqual({ ok: true, value: null });
  });

  it("never signs on append or read: signing happens only when sealing", async () => {
    const inner = signingKey();
    let signs = 0;
    const counting: KeyProvider = {
      ...inner.keyProvider,
      getPublicKey: (id) => inner.keyProvider.getPublicKey(id),
      sign: (id, data) => {
        signs += 1;
        return inner.keyProvider.sign(id, data);
      },
    };
    const app = await build({ signingKey: { keyProvider: counting, keyId: inner.keyId } });
    for (let i = 0; i < 5; i += 1) await post(app, event(`did:web:x:agents:${randomUUID()}`));
    await app.inject({ method: "GET", url: "/records" });
    expect(signs).toBe(0);
    await app.auditLedger.sealOnce();
    expect(signs).toBe(1);
  });

  it("keeps accepting records when sealing fails, and reports the failure", async () => {
    const inner = signingKey();
    const failing: KeyProvider = {
      ...inner.keyProvider,
      getPublicKey: (id) => inner.keyProvider.getPublicKey(id),
      sign: () => Promise.reject(new Error("ThrottlingException")),
    };
    const app = await build({ signingKey: { keyProvider: failing, keyId: inner.keyId } });
    expect((await post(app, event(`did:web:x:agents:${randomUUID()}`))).statusCode).toBe(201);
    expect(await app.auditLedger.sealOnce()).toEqual({
      ok: false,
      error: { code: "SIGNING_FAILED", reason: "ThrottlingException" },
    });
  });

  it("never forks under concurrent appends: the whole chain still verifies", async () => {
    const app = await build();
    const agentDid = `did:web:127.0.0.1%3A4824:agents:${randomUUID()}`;
    const responses = await Promise.all(
      Array.from({ length: 50 }, (_, i) => post(app, event(agentDid, `concurrent-${i}`))),
    );
    expect(responses.every((response) => response.statusCode === 201)).toBe(true);
    await app.auditLedger.sealOnce();

    const { result } = await pullVerified(app);
    expect(result.ok).toBe(true);
    expect(await recordsOf(app, agentDid)).toHaveLength(50);
  });

  it("seals on its own every interval, survives a failing tick, and stops when closed", async () => {
    const inner = signingKey();
    let failNext = true;
    const flaky: KeyProvider = {
      ...inner.keyProvider,
      getPublicKey: (id) => inner.keyProvider.getPublicKey(id),
      sign: (id, data) => {
        if (failNext) {
          failNext = false;
          return Promise.reject(new Error("ThrottlingException"));
        }
        return inner.keyProvider.sign(id, data);
      },
    };
    const app = await build({
      signingKey: { keyProvider: flaky, keyId: inner.keyId },
      sealIntervalMs: 20,
    });
    await post(app, event(`did:web:x:agents:${randomUUID()}`));
    const headSeq = async () => {
      const { result } = await pullVerified(app);
      if (!result.ok) throw new Error(result.error.code);
      return { head: result.value.headSeq, sealed: result.value.newestSeal?.seq };
    };
    // The first tick fails; a later one seals the head.
    await vi.waitFor(
      async () => {
        const { head, sealed } = await headSeq();
        expect(sealed).toBe(head);
      },
      { timeout: 5_000, interval: 25 },
    );
    expect(failNext).toBe(false);
    await app.close();
    // Another instance with no timer appends; the closed one must not seal it.
    const other = await build();
    await post(other, event(`did:web:x:agents:${randomUUID()}`));
    await new Promise((resolve) => setTimeout(resolve, 100));
    const { result } = await pullVerified(other);
    if (!result.ok) throw new Error(result.error.code);
    expect(result.value.unsealedCount).toBe(1);
  });

  it("serves a log that verifies even when an entry is appended and sealed between its two reads", async () => {
    // The server gets its own pool, so a hook can run exactly between the two
    // queries of one GET /records: another instance appends and seals there.
    const own = createDb(databaseUrl);
    const reader = await build({ db: own });
    const writer = await build();
    const query = own.$client.query.bind(own.$client) as (...args: unknown[]) => unknown;
    let armed = false;
    let seen = 0;
    (own.$client as unknown as { query: (...args: unknown[]) => unknown }).query = async (
      ...args: unknown[]
    ) => {
      if (armed && (seen += 1) === 2) {
        armed = false;
        await post(writer, event(`did:web:x:agents:${randomUUID()}`, "between-reads"));
        expect((await writer.auditLedger.sealOnce()).ok).toBe(true);
      }
      return query(...args);
    };
    try {
      await post(writer, event(`did:web:x:agents:${randomUUID()}`));
      await writer.auditLedger.sealOnce();
      armed = true;
      const { result } = await pullVerified(reader);
      expect(seen).toBeGreaterThanOrEqual(2);
      expect(result.ok ? "verified" : result.error.code).toBe("verified");
    } finally {
      await own.$client.end();
    }
  });

  it("keeps seals verifiable across a restart with the same key", async () => {
    const before = await build();
    await post(before, event(`did:web:x:agents:${randomUUID()}`));
    await before.auditLedger.sealOnce();
    const seal = (await before.inject({ method: "GET", url: "/records" })).json().seal as string;

    const after = await build();
    const { result } = await pullVerified(after, { held: [seal] });
    expect(result.ok).toBe(true);
  });
});

describe("tampering is detected (ADR 0017), each on its own database", () => {
  const adminUrl = databaseUrl;
  const created: { name: string; db: AuditDb }[] = [];
  afterAll(async () => {
    for (const { name, db: own } of created) {
      await own.$client.end();
      await dropTestDatabase(adminUrl, name);
    }
  });

  async function freshLedger() {
    const database = await createMigratedTestDatabase(adminUrl);
    const own = createDb(database.url);
    created.push({ name: database.name, db: own });
    const plane = createTestControlPlane(own);
    const key = await plane.key("service", ["audit:write"]);
    const app = await buildServer({
      db: own,
      controlPlaneAuth: plane.guard,
      didDomain: "127.0.0.1:4840",
      signingKey: signingKey(),
    });
    const agentDid = "did:web:127.0.0.1%3A4840:agents:a";
    for (let i = 1; i <= 3; i += 1) await post(app, event(agentDid, `action-${i}`), key);
    await app.auditLedger.sealOnce();
    const seal = (await app.inject({ method: "GET", url: "/records" })).json().seal as string;
    return { own, app, seal, plane };
  }

  it("the database itself refuses a fork: a second entry after the same one, or a reused seq", async () => {
    const { own } = await freshLedger();
    const [second] = await own
      .select()
      .from(auditRecords)
      .where(sql`${auditRecords.seq} = 2`);
    if (second === undefined) throw new Error("fixture");
    // The same row again under a new id: the database must refuse it.
    const copy = { ...second, id: undefined, createdAt: undefined };
    await expect(own.insert(auditRecords).values({ ...copy, seq: 99 })).rejects.toThrow();
    await expect(
      own.insert(auditRecords).values({ ...copy, prevHash: "ab".repeat(32) }),
    ).rejects.toThrow();
  });

  it("an entry edited in the database", async () => {
    const { own, app } = await freshLedger();
    await own.execute(
      sql`update audit_records set payload = replace(payload, 'action-2', 'nothing') where seq = 2`,
    );
    const { result } = await pullVerified(app);
    expect(result).toEqual({ ok: false, error: { code: "PAYLOAD_MISMATCH", seq: 2 } });
  });

  it("a middle entry deleted from the database", async () => {
    const { own, app } = await freshLedger();
    await own.delete(auditRecords).where(sql`${auditRecords.seq} = 2`);
    const { result } = await pullVerified(app);
    expect(result).toMatchObject({ ok: false, error: { code: "SEQUENCE_GAP" } });
  });

  it("the newest entries deleted together with their seal, against a seal the auditor kept", async () => {
    const { own, app, seal } = await freshLedger();
    await own.delete(auditRecords).where(sql`${auditRecords.seq} >= 2`);
    await own.delete(auditSeals);
    expect((await pullVerified(app)).result.ok).toBe(true); // looks fine on its own
    expect((await pullVerified(app, { held: [seal] })).result).toEqual({
      ok: false,
      error: { code: "TRUNCATED", sealSeq: 3, headSeq: 1 },
    });
  });

  it("the whole log rebuilt and re-sealed with the same key, against a seal the auditor kept", async () => {
    const { own, seal, plane } = await freshLedger();
    await own.delete(auditRecords);
    await own.delete(auditSeals);
    const key = await plane.key("service", ["audit:write"]);
    const rebuilt = await buildServer({
      db: own,
      controlPlaneAuth: plane.guard,
      didDomain: "127.0.0.1:4840",
      signingKey: signingKey(),
    });
    for (let i = 1; i <= 3; i += 1) {
      await post(rebuilt, event("did:web:127.0.0.1%3A4840:agents:a", `rewritten-${i}`), key);
    }
    await rebuilt.auditLedger.sealOnce();
    expect((await pullVerified(rebuilt)).result.ok).toBe(true); // a fresh seal vouches for it
    expect((await pullVerified(rebuilt, { held: [seal] })).result).toEqual({
      ok: false,
      error: { code: "DIVERGED", seq: 3 },
    });
  });

  it("rows stored before the ledger are chained once at boot, in order, with no reporter", async () => {
    const database = await createMigratedTestDatabase(adminUrl);
    const own = createDb(database.url);
    created.push({ name: database.name, db: own });
    const agentDid = "did:web:127.0.0.1%3A4841:agents:old";
    for (const action of ["old-1", "old-2"]) {
      await own.insert(auditRecords).values({
        agentDid,
        tool: "mock-slack",
        action,
        dataCategories: [],
        policyRule: "agent-tool-allowlist",
        decision: "allow",
        recordedAt: new Date("2026-10-01T00:00:00.000Z"),
      });
    }
    const plane = createTestControlPlane(own);
    const app = await buildServer({
      db: own,
      controlPlaneAuth: plane.guard,
      didDomain: "127.0.0.1:4841",
      signingKey: signingKey(),
    });
    await post(app, event(agentDid, "new"), await plane.key("service", ["audit:write"]));
    await app.auditLedger.sealOnce();

    const records = await recordsOf(app, agentDid);
    expect(records.map((record) => record.action)).toEqual(["old-1", "old-2", "new"]);
    expect(records[0]).not.toHaveProperty("reportedBy");
    expect(records[2]?.reportedBy?.name).toBe("test-service");
  });
});

describe("audit POST /records authentication (ADR 0008)", () => {
  it("refuses a forged record with no key, or with a wrong, expired or operator key, and never stores it", async () => {
    const app = await build();
    const keys = [
      undefined,
      await controlPlane.key("service", ["status:allocate"]),
      await controlPlane.key("service", ["audit:write"], {
        expiresAt: new Date("2020-01-01T00:00:00Z"),
      }),
      await controlPlane.key("operator", ["credentials:write", "agents:revoke"]),
      ["custos", "service", "0000000000000000", "A".repeat(43)].join("_"),
    ];
    for (const key of keys) {
      const agentDid = `did:web:127.0.0.1%3A4830:agents:${randomUUID()}`;
      const response = await app.inject({
        method: "POST",
        url: "/records",
        ...(key === undefined ? {} : { headers: bearer(key) }),
        payload: event(agentDid),
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({ error: { code: "UNAUTHORIZED" } });
      expect(await recordsOf(app, agentDid)).toEqual([]);
    }
  });

  it("keeps GET /records readable without a key (ADR 0008, decided 2026-10-02)", async () => {
    const response = await (await build()).inject({ method: "GET", url: "/records" });
    expect(response.statusCode).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBe("*");
  });
});

describe("audit control-plane records (ADR 0008 §7)", () => {
  it("stores an operator's action on an agent with its principal and no authority chain", async () => {
    const app = await build({ clock: fixedClock("2026-10-02T10:00:00.000Z") });
    const agentDid = `did:web:127.0.0.1%3A4833:agents:${randomUUID()}`;
    const principal = { kind: "operator", id: randomUUID().slice(0, 16), name: "lakshya" };
    const posted = await post(app, {
      agentDid,
      principal,
      action: "agents.revoke",
      dataCategories: [],
      policy: { rule: "control-plane-scope:agents:revoke", decision: "allow" },
      reason: "compromised",
    });
    expect(posted.statusCode).toBe(201);
    expect(await recordsOf(app, agentDid)).toEqual([
      {
        agentDid,
        principal,
        authorityChain: [],
        action: "agents.revoke",
        dataCategories: [],
        policy: { rule: "control-plane-scope:agents:revoke", decision: "allow" },
        reason: "compromised",
        recordedAt: "2026-10-02T10:00:00.000Z",
        reportedBy: { kind: "service", id: serviceKeyId(), name: "test-service" },
      },
    ]);
  });

  it("stores a control-plane action that names no agent", async () => {
    const app = await build();
    const name = `operator-${randomUUID()}`;
    const posted = await post(app, {
      principal: { kind: "operator", id: "0123456789abcdef", name },
      tool: "stripe",
      action: "credentials.store",
      dataCategories: [],
      policy: { rule: "control-plane-scope:credentials:write", decision: "allow" },
    });
    expect(posted.statusCode).toBe(201);
    const { result } = await pullVerified(app);
    if (!result.ok) throw new Error(result.error.code);
    const mine = result.value.records.filter((entry) => entry.record.principal?.name === name);
    expect(mine).toHaveLength(1);
    expect(mine[0]?.record).not.toHaveProperty("agentDid");
    expect(mine[0]?.record.authorityChain).toEqual([]);
  });

  it("400s an event that names neither an agent nor a principal", async () => {
    const response = await post(await build(), {
      tool: "stripe",
      action: "credentials.store",
      dataCategories: [],
      policy: { rule: "x", decision: "allow" },
    });
    expect(response.statusCode).toBe(400);
  });
});

// ADR 0017 part 2a: every seal is also copied to a separate seal store the
// audit service can only add to. Each test gets its own audit database and
// its own seal store database, reached through the real roles.
describe("seals copied outside the audit database (ADR 0017 part 2a)", () => {
  const adminUrl = databaseUrl;
  const cleanups: (() => Promise<void>)[] = [];
  afterAll(async () => {
    for (const cleanup of cleanups.reverse()) await cleanup();
  });

  async function fixture(options: { wrap?: (real: SealStore) => SealStore } = {}) {
    const audit = await createMigratedTestDatabase(adminUrl);
    const own = createDb(audit.url);
    const store = await createSealStoreTestDatabase(adminUrl);
    const sealer = createPostgresSealStore(store.sealerUrl);
    const auditor = createPostgresSealStore(store.auditorUrl);
    cleanups.push(async () => {
      await sealer.close();
      await auditor.close();
      await own.$client.end();
      await dropTestDatabase(adminUrl, audit.name);
      await dropTestDatabase(adminUrl, store.name);
    });
    const plane = createTestControlPlane(own);
    const key = await plane.key("service", ["audit:write"]);
    const build = (seed = 5) =>
      buildServer({
        db: own,
        controlPlaneAuth: plane.guard,
        didDomain: "127.0.0.1:4850",
        signingKey: signingKey(seed),
        sealStore: options.wrap?.(sealer) ?? sealer,
      });
    const app = await build();
    const log = "did:web:127.0.0.1%3A4850";
    const append = (target: App, action: string) =>
      post(target, event("did:web:127.0.0.1%3A4850:agents:a", action), key);
    return { own, app, build, sealer, auditor, log, append };
  }

  /** Verifies as `custos audit-log` does on a first run: every copy, read before the ledger. */
  async function verifyAgainstStore(app: App, auditor: SealStore, log: string) {
    const copies = await auditor.list(log, 1);
    return (await pullVerified(app, { held: [...copies] })).result;
  }

  const status = async (app: App): Promise<Record<string, unknown>> =>
    (await app.inject({ method: "GET", url: "/seals/status" })).json();

  it("copies every seal, oldest first, and reports how far copying has got", async () => {
    const { app, auditor, log, append } = await fixture();
    await append(app, "a");
    await app.auditLedger.sealOnce();
    await append(app, "b");
    await app.auditLedger.sealOnce();
    expect(await status(app)).toMatchObject({
      sealedThrough: 2,
      copiedThrough: 0,
      sealStore: "configured",
    });

    expect(await app.auditLedger.copyOnce()).toEqual({ ok: true, value: 2 });
    expect(await auditor.list(log, 1)).toHaveLength(2);
    expect(await status(app)).toMatchObject({
      sealedThrough: 2,
      copiedThrough: 2,
      oldestUncopiedSealedAt: null,
      lastCopyError: null,
    });
    expect(await app.auditLedger.copyOnce()).toEqual({ ok: true, value: 0 });
    expect((await verifyAgainstStore(app, auditor, log)).ok).toBe(true);
  });

  it("blocks nothing while the seal store is down, and catches up when it is back", async () => {
    let up = false;
    const { app, auditor, log, append } = await fixture({
      wrap: (real) => ({
        ...real,
        put: (copy) => (up ? real.put(copy) : Promise.reject(new Error("ECONNREFUSED"))),
      }),
    });
    expect((await append(app, "a")).statusCode).toBe(201);
    expect((await app.auditLedger.sealOnce()).ok).toBe(true);
    expect(await app.auditLedger.copyOnce()).toEqual({
      ok: false,
      error: { code: "COPY_FAILED", reason: "ECONNREFUSED" },
    });
    expect((await append(app, "b")).statusCode).toBe(201);
    expect((await app.auditLedger.sealOnce()).ok).toBe(true);
    expect(await status(app)).toMatchObject({
      copiedThrough: 0,
      lastCopyError: { code: "COPY_FAILED" },
    });
    // The open status route shows a code, never the store's own error text.
    expect(JSON.stringify(await status(app))).not.toContain("ECONNREFUSED");
    expect((await status(app)).oldestUncopiedSealedAt).not.toBeNull();

    up = true;
    expect(await app.auditLedger.copyOnce()).toEqual({ ok: true, value: 2 });
    expect(await auditor.list(log, 1)).toHaveLength(2);
    expect(await status(app)).toMatchObject({ copiedThrough: 2, lastCopyError: null });
  });

  it("says so, and copies nothing, when no seal store is configured", async () => {
    const app = await build();
    expect(await app.auditLedger.copyOnce()).toMatchObject({ ok: false });
    expect(await status(app)).toMatchObject({ sealStore: "not configured" });
  });

  it("detects the newest entries deleted with the audit database's own seals, from the seal store", async () => {
    const { own, app, auditor, log, append } = await fixture();
    for (const action of ["a", "b", "c"]) await append(app, action);
    await app.auditLedger.sealOnce();
    await app.auditLedger.copyOnce();

    // Someone with access to the audit database removes the newest entries and every seal there.
    await own.delete(auditRecords).where(sql`${auditRecords.seq} >= 2`);
    await own.delete(auditSeals);

    expect((await pullVerified(app)).result.ok).toBe(true); // looks fine without the store
    expect(await verifyAgainstStore(app, auditor, log)).toEqual({
      ok: false,
      error: { code: "TRUNCATED", sealSeq: 3, headSeq: 1 },
    });
  });

  it("detects a log rebuilt and re-sealed with the same key, even when the forged seal is copied too", async () => {
    const { own, app, build, auditor, log, append } = await fixture();
    for (const action of ["a", "b"]) await append(app, action);
    await app.auditLedger.sealOnce();
    await app.auditLedger.copyOnce();

    // The audit service's own identity: it holds the key and may add copies.
    await own.delete(auditRecords);
    await own.delete(auditSeals);
    const rebuilt = await build();
    for (const action of ["x", "y", "z"]) await append(rebuilt, action);
    await rebuilt.auditLedger.sealOnce();
    expect(await rebuilt.auditLedger.copyOnce()).toEqual({ ok: true, value: 1 });

    // The newest copy alone vouches for the rewritten log...
    const newest = (await auditor.list(log, 3)).slice(-1);
    expect((await pullVerified(rebuilt, { held: newest })).result.ok).toBe(true);
    // ...but the older copy, which cannot be removed, contradicts it.
    expect(await verifyAgainstStore(rebuilt, auditor, log)).toEqual({
      ok: false,
      error: { code: "DIVERGED", seq: 2 },
    });
  });

  it("reports a different seal already copied at the same position, and never overwrites it", async () => {
    const { own, app, build, auditor, log, append } = await fixture();
    await append(app, "a");
    await app.auditLedger.sealOnce();
    await app.auditLedger.copyOnce();
    const [original] = await auditor.list(log, 1);

    await own.delete(auditRecords);
    await own.delete(auditSeals);
    const rebuilt = await build();
    await append(rebuilt, "rewritten");
    await rebuilt.auditLedger.sealOnce();
    expect(await rebuilt.auditLedger.copyOnce()).toMatchObject({
      ok: false,
      error: { code: "SEAL_CONFLICT", reason: expect.stringMatching(/different seal/) },
    });
    expect(await auditor.list(log, 1)).toEqual([original]);
  });

  describe("key rotation (ADR 0017)", () => {
    const keyOf = async (app: App) =>
      ((await app.inject({ method: "GET", url: "/.well-known/did.json" })).json() as DidWebDocument)
        .verificationMethod[0].publicKeyMultibase;

    it("after a restart on a new key: serves no seal until the head moves, never re-seals, copies only new-key seals", async () => {
      const { app, build, auditor, log, append } = await fixture();
      await append(app, "a");
      await app.auditLedger.sealOnce();
      const firstKey = await keyOf(app);

      // Restarted on a new key before the old seal was copied.
      const restarted = await build(6);
      const secondKey = await keyOf(restarted);
      expect(secondKey).not.toBe(firstKey);
      expect((await restarted.inject({ method: "GET", url: "/records" })).json().seal).toBeNull();
      expect(await restarted.auditLedger.sealOnce()).toEqual({ ok: true, value: null });

      await append(restarted, "b");
      expect(await restarted.auditLedger.sealOnce()).toEqual({ ok: true, value: 2 });
      expect(await restarted.auditLedger.copyOnce()).toEqual({ ok: true, value: 1 });
      expect(await status(restarted)).toMatchObject({ copiedThrough: 2, notCopyable: [1] });
      const copies = await auditor.list(log, 1);
      expect(copies).toHaveLength(1);

      // An auditor who trusts both keys verifies everything.
      const { result } = await pullVerified(restarted, {
        held: [...copies],
        trustedKeys: [firstKey, secondKey],
      });
      expect(result).toMatchObject({ ok: true, value: { newestSeal: { seq: 2, key: secondKey } } });
    });

    it("never copies a seal whose key column was set to the current key but does not verify under it", async () => {
      const { own, app, auditor, log, append } = await fixture();
      await append(app, "a");
      await app.auditLedger.sealOnce();
      const [row] = await own.select().from(auditSeals);
      if (row === undefined) throw new Error("fixture");
      // Someone with only audit-database access plants a junk seal labelled with the current key.
      await own.delete(auditSeals);
      await own.insert(auditSeals).values({ ...row, seal: `${row.seal.split(".")[0]}.AAAA` });

      expect(await app.auditLedger.copyOnce()).toEqual({ ok: true, value: 0 });
      expect(await auditor.list(log, 1)).toEqual([]);
      expect(await status(app)).toMatchObject({ notCopyable: [1] });
    });

    it("still reports a log rewritten under a new key once that key is accepted, from the old copies", async () => {
      const { own, app, build, auditor, log, append } = await fixture();
      for (const action of ["a", "b"]) await append(app, action);
      await app.auditLedger.sealOnce();
      await app.auditLedger.copyOnce();
      const firstKey = await keyOf(app);

      // The service's identity rotates the key, rewrites the log, seals and copies under the new key.
      await own.delete(auditRecords);
      await own.delete(auditSeals);
      const rotated = await build(6);
      for (const action of ["x", "y", "z"]) await append(rotated, action);
      await rotated.auditLedger.sealOnce();
      await rotated.auditLedger.copyOnce();
      const secondKey = await keyOf(rotated);

      const copies = await auditor.list(log, 1);
      expect(
        (await pullVerified(rotated, { held: [...copies], trustedKeys: [firstKey, secondKey] }))
          .result,
      ).toEqual({
        ok: false,
        error: { code: "DIVERGED", seq: 2 },
      });
    });
  });
});

// ADR 0017 part 2b: the copies in a versioned S3 bucket with Object Lock
// (here the stand-in from @custos/audit-client/testing). Its administrator
// cannot delete a locked seal, but can hide it behind a delete marker and put
// another in its place; the auditor reads every version, so neither works.
describe("seals copied to S3 Object Lock (ADR 0017 part 2b)", () => {
  const cleanups: (() => Promise<void>)[] = [];
  afterAll(async () => {
    for (const cleanup of cleanups.reverse()) await cleanup();
  });

  async function fixture() {
    const audit = await createMigratedTestDatabase(databaseUrl);
    const own = createDb(audit.url);
    cleanups.push(async () => {
      await own.$client.end();
      await dropTestDatabase(databaseUrl, audit.name);
    });
    const s3 = fakeS3({ pageSize: 2 });
    const store = createS3SealStore({ client: s3.client, bucket: "seals" });
    const plane = createTestControlPlane(own);
    const key = await plane.key("service", ["audit:write"]);
    const build = () =>
      buildServer({
        db: own,
        controlPlaneAuth: plane.guard,
        didDomain: "127.0.0.1:4851",
        signingKey: signingKey(5),
        sealStore: store,
      });
    const app = await build();
    const log = "did:web:127.0.0.1%3A4851";
    const append = (target: App, action: string) =>
      post(target, event("did:web:127.0.0.1%3A4851:agents:a", action), key);
    /** What the seal store's administrator can do under Object Lock: add a delete marker. */
    const hide = (seq: number) => {
      const objectKey = `seals/${encodeURIComponent(log)}/${String(seq).padStart(20, "0")}.json`;
      s3.objects.get(objectKey)!.push({ versionId: `marker-${seq}`, body: undefined });
    };
    const verify = async (target: App) =>
      (await pullVerified(target, { held: [...(await store.list(log, 1))] })).result;
    return { own, app, build, log, append, hide, verify };
  }

  it("copies every seal and verifies against the copies", async () => {
    const { app, append, verify } = await fixture();
    for (const action of ["a", "b", "c"]) {
      await append(app, action);
      await app.auditLedger.sealOnce();
    }
    expect(await app.auditLedger.copyOnce()).toEqual({ ok: true, value: 3 });
    expect((await verify(app)).ok).toBe(true);
  });

  it("detects the newest entries deleted with every seal, even with the copy hidden", async () => {
    const { own, app, append, hide, verify } = await fixture();
    for (const action of ["a", "b", "c"]) await append(app, action);
    await app.auditLedger.sealOnce();
    await app.auditLedger.copyOnce();

    await own.delete(auditRecords).where(sql`${auditRecords.seq} >= 2`);
    await own.delete(auditSeals);
    hide(3);

    expect(await verify(app)).toEqual({
      ok: false,
      error: { code: "TRUNCATED", sealSeq: 3, headSeq: 1 },
    });
  });

  it("detects a rewritten log whose seal was put in place of the hidden original", async () => {
    const { own, app, build, append, hide, verify } = await fixture();
    for (const action of ["a", "b"]) await append(app, action);
    await app.auditLedger.sealOnce();
    await app.auditLedger.copyOnce();

    // The audit service's key and the seal store's administrator, together.
    await own.delete(auditRecords);
    await own.delete(auditSeals);
    hide(2);
    const rebuilt = await build();
    for (const action of ["x", "y"]) await append(rebuilt, action);
    await rebuilt.auditLedger.sealOnce();
    // With the original hidden, If-None-Match lets the forged seal in.
    expect(await rebuilt.auditLedger.copyOnce()).toEqual({ ok: true, value: 1 });

    expect(await verify(rebuilt)).toEqual({ ok: false, error: { code: "DIVERGED", seq: 2 } });
  });
});

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
import { createMigratedTestDatabase, dropTestDatabase } from "@custos/vitest-config/hermetic-db";
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
async function pullVerified(app: App, options: { agentDid?: string; held?: string[] } = {}) {
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
  const key = multibaseToPublicKey(did.verificationMethod[0].publicKeyMultibase);
  if (!key.ok) throw new Error("fixture: unreadable DID key");
  return {
    body,
    result: verifyAuditLedger({
      entries: body.entries,
      seals: [...(body.seal === null ? [] : [body.seal]), ...(options.held ?? [])],
      publicKey: key.value,
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

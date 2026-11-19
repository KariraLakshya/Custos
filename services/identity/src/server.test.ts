import { randomUUID } from "node:crypto";
import {
  buildRegistrationRequest,
  createLocalKeyProvider,
  err,
  generateKeyPair,
  issuePossessionProof,
  ok,
  publicKeyToMultibase,
  REGISTRATION_PROOF_TYPE,
  sign,
  verifyCredential,
  type DidWebDocument,
  type SignedCredential,
} from "@custos/core";
import type { AuditEvent, AuditReporter } from "@custos/audit-client";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { createDb } from "./db/client.js";
import { agents } from "./db/schema.js";
import { buildServer } from "./server.js";
import type { StatusAllocator } from "./agents/status-allocator.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);

const controlPlane = createTestControlPlane(db);
let operatorKey: string;

beforeAll(async () => {
  operatorKey = await controlPlane.key("operator", ["agents:register"]);
});

afterAll(async () => {
  await db.$client.end();
});

const DOMAIN = "identity.custos.example";
const ISSUER_DID = `did:web:${DOMAIN}`;
const SEED = new Uint8Array(32).fill(3);

function issuerKey(seed: Uint8Array = SEED) {
  return {
    keyProvider: createLocalKeyProvider({ importedKeys: { issuer: seed } }),
    keyId: "issuer",
  };
}

/**
 * Stands in for the revocation service, so identity's own tests do not need
 * it running. Hands out indexes from a counter, as the real service does, and
 * counts allocations so a test can prove a bad request allocated nothing.
 */
function fakeStatusAllocator(): StatusAllocator & { allocations: number } {
  let nextIndex = 0;
  const allocator = {
    allocations: 0,
    allocate: async () => {
      allocator.allocations += 1;
      return ok({
        statusListIndex: nextIndex++,
        statusListCredential: "http://127.0.0.1:4503/status/revocation",
      });
    },
  };
  return allocator;
}

const unreachableStatusAllocator: StatusAllocator = {
  allocate: async () =>
    err({ code: "STATUS_ALLOCATION_FAILED", reason: "revocation service unreachable" }),
};

function buildTestServer(
  options: {
    statusAllocator?: StatusAllocator;
    seed?: Uint8Array;
    didDomain?: string;
    auditReporter?: AuditReporter;
  } = {},
) {
  return buildServer({
    auditReporter: options.auditReporter ?? { report: () => {} },
    db,
    controlPlaneAuth: controlPlane.guard,
    didDomain: options.didDomain ?? DOMAIN,
    issuerKey: issuerKey(options.seed),
    statusAllocator: options.statusAllocator ?? fakeStatusAllocator(),
  });
}

type App = Awaited<ReturnType<typeof buildTestServer>>;

/** The fields the tamper tests rewrite; everything else passes through untouched. */
interface TamperableCredential {
  credentialSubject: { id: string; publicKeyMultibase: string };
  credentialStatus: { statusListIndex: string };
}

async function register(app: App, body: unknown) {
  return app.inject({
    method: "POST",
    url: "/agents",
    headers: bearer(operatorKey),
    payload: body as object,
  });
}

async function validRequest(overrides: { audience?: string; now?: Date } = {}) {
  return buildRegistrationRequest({
    audience: overrides.audience ?? ISSUER_DID,
    now: overrides.now ?? new Date(),
  });
}

async function issuerDocument(app: App): Promise<DidWebDocument> {
  return (await app.inject({ method: "GET", url: "/.well-known/did.json" })).json();
}

describe("identity service", () => {
  it("responds to /health", async () => {
    const app = await buildTestServer();
    const response = await app.inject({ method: "GET", url: "/health" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "identity" });
  });

  it("publishes its own issuer DID document at /.well-known/did.json", async () => {
    const app = await buildTestServer();
    const document = await issuerDocument(app);

    expect(document.id).toBe(ISSUER_DID);
    const { keyProvider, keyId } = issuerKey();
    expect(document.verificationMethod[0]?.publicKeyMultibase).toBe(
      publicKeyToMultibase(await keyProvider.getPublicKey(keyId)),
    );
  });

  describe("registration (ADR 0007: agent-held key, issuer-signed credential)", () => {
    it("issues a credential signed by the identity service, naming the agent and embedding its key", async () => {
      const app = await buildTestServer();
      const request = await validRequest();

      const response = await register(app, request.body);

      expect(response.statusCode).toBe(201);
      const registered = response.json();
      const credential = registered.credential as SignedCredential;
      expect(registered.did).toBe(`${ISSUER_DID}:agents:${registered.id}`);
      expect(credential.issuer).toBe(ISSUER_DID);
      expect(credential.credentialSubject).toEqual({
        id: registered.did,
        publicKeyMultibase: request.body.publicKey,
      });
      expect(
        (await verifyCredential({ credential, didDocument: await issuerDocument(app) })).ok,
      ).toBe(true);
    });

    it("never receives the agent's private key — the response carries only public material", async () => {
      const app = await buildTestServer();
      const request = await validRequest();

      const response = await register(app, request.body);

      expect(response.body).not.toContain(Buffer.from(request.secretKey).toString("hex"));
      expect(response.body).not.toContain(Buffer.from(request.secretKey).toString("base64url"));
    });

    it("still publishes the agent's DID document, holding the agent's own key", async () => {
      const app = await buildTestServer();
      const request = await validRequest();
      const registered = (await register(app, request.body)).json();

      const didDocument = (
        await app.inject({ method: "GET", url: `/agents/${registered.id}/did.json` })
      ).json();

      expect(didDocument.id).toBe(registered.did);
      expect(didDocument.verificationMethod[0].publicKeyMultibase).toBe(request.body.publicKey);
    });

    it("keeps issued credentials valid across a restart with the same issuer key", async () => {
      const before = await buildTestServer();
      const credential = (await register(before, (await validRequest()).body)).json()
        .credential as SignedCredential;

      const afterRestart = await buildTestServer();

      expect(
        (await verifyCredential({ credential, didDocument: await issuerDocument(afterRestart) }))
          .ok,
      ).toBe(true);
    });

    it("invalidates credentials if the issuer key changes — the seed is what makes restarts safe", async () => {
      const before = await buildTestServer();
      const credential = (await register(before, (await validRequest()).body)).json()
        .credential as SignedCredential;

      const withNewKey = await buildTestServer({ seed: new Uint8Array(32).fill(4) });

      expect(
        (await verifyCredential({ credential, didDocument: await issuerDocument(withNewKey) })).ok,
      ).toBe(false);
    });

    it.each([
      [
        "the subject (who the agent is)",
        (c: TamperableCredential) => (c.credentialSubject.id = "did:web:attacker.example"),
      ],
      [
        "the embedded agent key",
        (c: TamperableCredential) =>
          (c.credentialSubject.publicKeyMultibase = publicKeyToMultibase(
            generateKeyPair().publicKey,
          )),
      ],
      [
        "the status list index",
        (c: TamperableCredential) => (c.credentialStatus.statusListIndex = "999999"),
      ],
    ])("detects tampering with %s", async (_label, tamper) => {
      const app = await buildTestServer();
      const credential = (await register(app, (await validRequest()).body)).json().credential;
      const tampered = structuredClone(credential);
      tamper(tampered);

      const verified = await verifyCredential({
        credential: tampered,
        didDocument: await issuerDocument(app),
      });
      expect(verified.ok).toBe(false);
    });

    it("embeds a revocation status entry in every issued credential", async () => {
      const app = await buildTestServer();
      const credential = (await register(app, (await validRequest()).body)).json()
        .credential as SignedCredential;

      expect(credential.credentialStatus?.type).toBe("BitstringStatusListEntry");
      expect(credential.credentialStatus?.statusPurpose).toBe("revocation");
    });
  });

  describe("registration rejects", () => {
    it("a request with no body", async () => {
      const app = await buildTestServer();
      const response = await app.inject({
        method: "POST",
        url: "/agents",
        headers: bearer(operatorKey),
      });

      expect(response.statusCode).toBe(400);
      expect(response.json().error.code).toBe("INVALID_INPUT");
    });

    it("an oversized proof, before parsing it", async () => {
      const app = await buildTestServer();
      const request = await validRequest();

      const response = await register(app, { ...request.body, proof: "a".repeat(5000) });

      expect(response.statusCode).toBe(400);
      expect(response.json().error.code).toBe("INVALID_INPUT");
    });

    it("a public key that is not an Ed25519 multibase key", async () => {
      const app = await buildTestServer();
      const request = await validRequest();

      const response = await register(app, { ...request.body, publicKey: "zNotAKey" });

      expect(response.statusCode).toBe(400);
      expect(response.json().error.code).toBe("INVALID_PUBLIC_KEY");
    });

    it("a proof made with a different key than the one submitted — no possession, no agent", async () => {
      const app = await buildTestServer();
      const victim = generateKeyPair();
      const attackersRequest = await validRequest();

      const response = await register(app, {
        publicKey: publicKeyToMultibase(victim.publicKey),
        proof: attackersRequest.body.proof,
      });

      expect(response.statusCode).toBe(401);
      expect(response.json().error).toEqual({
        code: "INVALID_REGISTRATION_PROOF",
        reason: "SIGNATURE_INVALID",
      });
    });

    it("a proof addressed to a different identity service", async () => {
      const app = await buildTestServer();
      const request = await validRequest({ audience: "did:web:other.example" });

      const response = await register(app, request.body);

      expect(response.statusCode).toBe(401);
      expect(response.json().error.reason).toBe("WRONG_AUDIENCE");
    });

    it("a stale proof, judged by the injected clock", async () => {
      const serverNow = new Date("2026-09-25T12:00:00Z");
      const app = await buildServer({
        auditReporter: { report: () => {} },
        db,
        controlPlaneAuth: controlPlane.guard,
        didDomain: DOMAIN,
        issuerKey: issuerKey(),
        statusAllocator: fakeStatusAllocator(),
        clock: { now: () => serverNow },
        registrationProofMaxSkewSeconds: 60,
      });
      const request = await validRequest({ now: new Date("2026-09-25T11:58:59Z") });

      const response = await register(app, request.body);

      expect(response.statusCode).toBe(401);
      expect(response.json().error.reason).toBe("STALE");
    });

    it("a validly signed proof of a different type", async () => {
      const app = await buildTestServer();
      const { publicKey, secretKey } = generateKeyPair();
      const proof = await issuePossessionProof({
        claims: {
          typ: "custos-token-request-proof",
          aud: ISSUER_DID,
          iat: Math.floor(Date.now() / 1000),
          jti: "j-1",
        },
        sign: async (data) => sign(data, secretKey),
      });
      if (!proof.ok) throw new Error("proof");

      const response = await register(app, {
        publicKey: publicKeyToMultibase(publicKey),
        proof: proof.value,
      });

      expect(response.statusCode).toBe(401);
      expect(response.json().error.reason).toBe("WRONG_TYPE");
    });

    it("a replayed registration request — one key is one agent", async () => {
      const app = await buildTestServer();
      const request = await validRequest();

      expect((await register(app, request.body)).statusCode).toBe(201);
      const replayed = await register(app, request.body);

      expect(replayed.statusCode).toBe(409);
      expect(replayed.json().error.code).toBe("KEY_ALREADY_REGISTERED");
    });

    it("the second of two concurrent registrations of one key", async () => {
      const app = await buildTestServer();
      const request = await validRequest();

      const statuses = (
        await Promise.all([register(app, request.body), register(app, request.body)])
      ).map((response) => response.statusCode);

      expect(statuses.sort()).toEqual([201, 409]);
    });

    it("a bad request without allocating a status list index", async () => {
      const allocator = fakeStatusAllocator();
      const app = await buildTestServer({ statusAllocator: allocator });
      const request = await validRequest({ audience: "did:web:other.example" });

      await register(app, request.body);

      expect(allocator.allocations).toBe(0);
    });

    // An agent that exists but has no status list entry could never be
    // revoked, so registration must fail rather than issue one.
    it("registration when the revocation service is unreachable", async () => {
      const app = await buildTestServer({ statusAllocator: unreachableStatusAllocator });

      const response = await register(app, (await validRequest()).body);

      expect(response.statusCode).toBe(502);
      expect(response.json().error.code).toBe("STATUS_ALLOCATION_FAILED");
    });
  });

  it("404s a did.json request for an unknown agent id", async () => {
    const app = await buildTestServer();
    const response = await app.inject({
      method: "GET",
      url: "/agents/00000000-0000-0000-0000-000000000000/did.json",
    });
    expect(response.statusCode).toBe(404);
  });

  it("400s a did.json request for a malformed agent id", async () => {
    const app = await buildTestServer();
    const response = await app.inject({ method: "GET", url: "/agents/not-a-uuid/did.json" });
    expect(response.statusCode).toBe(400);
  });

  it("uses REGISTRATION_PROOF_TYPE for registration proofs", () => {
    expect(REGISTRATION_PROOF_TYPE).toBe("custos-registration-proof");
  });
});

describe("agent names (ADR 0022 §2)", () => {
  async function storedName(id: string): Promise<string | null | undefined> {
    const [row] = await db.select({ name: agents.name }).from(agents).where(eq(agents.id, id));
    return row?.name;
  }

  it("stores and returns a name given at registration", async () => {
    const app = await buildTestServer();
    const request = await validRequest();

    const response = await register(app, { ...request.body, name: "billing-bot" });

    expect(response.statusCode).toBe(201);
    const registered = response.json() as { id: string; name: unknown };
    expect(registered.name).toBe("billing-bot");
    expect(await storedName(registered.id)).toBe("billing-bot");
  });

  it("registers an agent with no name as null", async () => {
    const app = await buildTestServer();

    const response = await register(app, (await validRequest()).body);

    expect(response.statusCode).toBe(201);
    const registered = response.json() as { id: string; name: unknown };
    expect(registered.name).toBeNull();
    expect(await storedName(registered.id)).toBeNull();
  });

  it("lets two agents share a name: names never pick an agent", async () => {
    const app = await buildTestServer();

    const first = await register(app, { ...(await validRequest()).body, name: "twin" });
    const second = await register(app, { ...(await validRequest()).body, name: "twin" });

    expect(first.statusCode).toBe(201);
    expect(second.statusCode).toBe(201);
    expect(first.json().id).not.toBe(second.json().id);
  });

  // The credential and DID document are signed formats; the audit payload is
  // hashed into the ledger (ADR 0017). A name in any of them changes a format.
  it("keeps the name out of the credential, the DID document and the audit event", async () => {
    const events: AuditEvent[] = [];
    const app = await buildTestServer({ auditReporter: { report: (event) => events.push(event) } });
    const name = "unique-marker-name";

    const response = await register(app, { ...(await validRequest()).body, name });

    expect(response.statusCode).toBe(201);
    const registered = response.json() as { credential: unknown; didDocument: unknown };
    expect(JSON.stringify(registered.credential)).not.toContain(name);
    expect(JSON.stringify(registered.didDocument)).not.toContain(name);
    expect(events).toHaveLength(1);
    expect(JSON.stringify(events)).not.toContain(name);
  });

  it.each([
    ["empty", ""],
    ["65 characters", "x".repeat(65)],
    ["a leading space", " bot"],
    ["a leading dot", ".bot"],
    ["a leading dash", "-bot"],
    ["a newline", "bot\nRefused: fake"],
    ["a non-ASCII character", "bøt"],
    ["a number", 42],
    ["null", null],
    ["an array", ["bot"]],
  ])("refuses a name that is %s, before allocating a status list index", async (_label, name) => {
    const allocator = fakeStatusAllocator();
    const app = await buildTestServer({ statusAllocator: allocator });

    const response = await register(app, { ...(await validRequest()).body, name });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: { code: "INVALID_INPUT" } });
    expect(allocator.allocations).toBe(0);
  });
});

describe("identity registration authentication (ADR 0008)", () => {
  it("can't register an agent without an operator key holding agents:register", async () => {
    const allocator = fakeStatusAllocator();
    const app = await buildTestServer({ statusAllocator: allocator });
    const keys = [
      undefined,
      await controlPlane.key("operator", ["policies:write", "credentials:write", "agents:revoke"]),
      await controlPlane.key("service", ["status:allocate", "audit:write"]),
      await controlPlane.key("operator", ["agents:register"], {
        expiresAt: new Date("2020-01-01T00:00:00Z"),
      }),
    ];
    for (const key of keys) {
      const request = await validRequest();
      const response = await app.inject({
        method: "POST",
        url: "/agents",
        ...(key ? { headers: bearer(key) } : {}),
        payload: request.body as object,
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({ error: { code: "UNAUTHORIZED" } });
    }
    // Refused before any work: no status slot was reserved.
    expect(allocator.allocations).toBe(0);
  });

  it("refuses to build without a service key when no allocator is injected", async () => {
    await expect(
      buildServer({
        db,
        controlPlaneAuth: controlPlane.guard,
        didDomain: DOMAIN,
        issuerKey: issuerKey(),
      }),
    ).rejects.toThrow("serviceKey or mtlsFetch is required");
  });
});

describe("identity registration auditing (ADR 0008 §7)", () => {
  it("audits a registration with the operator who approved it, and a scope denial", async () => {
    const events: AuditEvent[] = [];
    const app = await buildTestServer({ auditReporter: { report: (event) => events.push(event) } });

    const registered = await register(app, (await validRequest()).body);
    expect(registered.statusCode).toBe(201);
    const agentDid = (registered.json() as { did: string }).did;

    const policiesOnly = await controlPlane.key("operator", ["policies:write"]);
    const refused = await app.inject({
      method: "POST",
      url: "/agents",
      headers: bearer(policiesOnly),
      payload: (await validRequest()).body as object,
    });
    expect(refused.statusCode).toBe(401);
    // Unauthenticated: logged, never audited.
    await app.inject({
      method: "POST",
      url: "/agents",
      payload: (await validRequest()).body as object,
    });

    expect(events).toEqual([
      {
        principal: { kind: "operator", id: operatorKey.split("_")[2], name: "test-operator" },
        action: "agents.register",
        dataCategories: [],
        policy: { rule: "control-plane-scope:agents:register", decision: "allow" },
        agentDid,
      },
      {
        principal: { kind: "operator", id: policiesOnly.split("_")[2], name: "test-operator" },
        action: "agents.register",
        dataCategories: [],
        policy: { rule: "control-plane-scope:agents:register", decision: "deny" },
      },
    ]);
  });

  it("refuses to build without a service key when no audit reporter is injected", async () => {
    await expect(
      buildServer({
        db,
        controlPlaneAuth: controlPlane.guard,
        didDomain: DOMAIN,
        issuerKey: issuerKey(),
        statusAllocator: fakeStatusAllocator(),
      }),
    ).rejects.toThrow("serviceKey or mtlsFetch is required when auditReporter is not injected");
  });
});

describe("GET /agents (ADR 0022 §2, §3: agents:read, never open)", () => {
  // A guard of its own, so this block's refused keys don't count towards
  // another block's lockout (ADR 0008 §8).
  const readPlane = createTestControlPlane(db);
  let readKey: string;
  let app: App;

  beforeAll(async () => {
    readKey = await readPlane.key("operator", ["agents:read"]);
    app = await buildServer({
      auditReporter: { report: () => {} },
      db,
      controlPlaneAuth: readPlane.guard,
      didDomain: DOMAIN,
      issuerKey: issuerKey(),
      statusAllocator: fakeStatusAllocator(),
    });
  });

  /** `key: null` sends no key at all (an explicit `undefined` would take the default). */
  async function list(query = "", key: string | null = readKey) {
    return app.inject({
      method: "GET",
      url: `/agents${query}`,
      ...(key === null ? {} : { headers: bearer(key) }),
    });
  }

  async function registered(name?: string): Promise<{ id: string; did: string }> {
    const body = (await validRequest()).body;
    const response = await register(app, name === undefined ? body : { ...body, name });
    expect(response.statusCode).toBe(201);
    return response.json() as { id: string; did: string };
  }

  it.each([
    ["no key", async () => null],
    ["a malformed key", async () => "not-a-custos-key"],
    [
      "a wrong key (right id, wrong secret)",
      async () => `${readKey.split("_").slice(0, 3).join("_")}_${"x".repeat(43)}`,
    ],
    [
      "an expired key",
      async () =>
        readPlane.key("operator", ["agents:read"], { expiresAt: new Date("2020-01-01T00:00:00Z") }),
    ],
    [
      "a key with every other operator scope but not agents:read",
      async () =>
        readPlane.key("operator", [
          "agents:register",
          "agents:revoke",
          "credentials:write",
          "policies:write",
          "audit:read",
          "revocations:read",
          "policies:read",
        ]),
    ],
  ])("refuses %s with the guard's one 401, showing nothing", async (_label, makeKey) => {
    const agent = await registered("hidden-bot");
    const response = await list(`?id=${agent.id}`, await makeKey());
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: { code: "UNAUTHORIZED" } });
    expect(response.body).not.toContain(agent.did);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("shows an agent by id: id, DID, name, registration time and who registered it", async () => {
    const before = Date.now();
    const agent = await registered("billing-bot");

    const response = await list(`?id=${agent.id}`);

    expect(response.statusCode).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    const page = response.json() as {
      agents: Record<string, unknown>[];
      nextCursor: string | null;
    };
    expect(page.nextCursor).toBeNull();
    expect(page.agents).toHaveLength(1);
    const [shown] = page.agents;
    // Exactly these fields: never the credential, the DID document or the key.
    expect(Object.keys(shown!).sort()).toEqual([
      "did",
      "id",
      "name",
      "registeredAt",
      "registeredBy",
    ]);
    expect(shown).toMatchObject({
      id: agent.id,
      did: agent.did,
      name: "billing-bot",
      registeredBy: { kind: "operator", id: operatorKey.split("_")[2], name: "test-operator" },
    });
    const registeredAt = Date.parse(shown!.registeredAt as string);
    expect(registeredAt).toBeGreaterThanOrEqual(before - 5_000);
    expect(registeredAt).toBeLessThanOrEqual(Date.now() + 5_000);
  });

  it("stores the registering principal in the agent's row", async () => {
    const agent = await registered();
    const [row] = await db.select().from(agents).where(eq(agents.id, agent.id));
    expect(row).toMatchObject({
      registeredByKind: "operator",
      registeredById: operatorKey.split("_")[2],
      registeredByName: "test-operator",
    });
  });

  it("shows an agent by DID, and an unnamed agent's name as null", async () => {
    const agent = await registered();
    const page = (await list(`?did=${encodeURIComponent(agent.did)}`)).json() as {
      agents: { id: string; name: unknown }[];
    };
    expect(page.agents.map((a) => a.id)).toEqual([agent.id]);
    expect(page.agents[0]!.name).toBeNull();
  });

  it("shows an agent registered before migration 0015 with registeredBy null", async () => {
    const id = randomUUID();
    await db.insert(agents).values({
      id,
      did: `did:web:${DOMAIN}:agents:${id}`,
      didDocument: {},
      credential: {},
    });
    const page = (await list(`?id=${id}`)).json() as { agents: { registeredBy: unknown }[] };
    expect(page.agents).toHaveLength(1);
    expect(page.agents[0]!.registeredBy).toBeNull();
  });

  it("answers an unknown id or DID with an empty list, not an error", async () => {
    const unknownId = "00000000-0000-4000-8000-000000000000";
    for (const query of [
      `?id=${unknownId}`,
      `?did=${encodeURIComponent(`did:web:${DOMAIN}:agents:${unknownId}`)}`,
    ]) {
      const response = await list(query);
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ agents: [], nextCursor: null });
    }
  });

  it("pages the whole list by id: bounded pages, each agent once, in order", async () => {
    const mine = [(await registered()).id, (await registered()).id, (await registered()).id];

    const first = (await list("?limit=2")).json() as {
      agents: { id: string }[];
      nextCursor: string | null;
    };
    expect(first.agents).toHaveLength(2);
    expect(first.nextCursor).toBe(first.agents[1]!.id);

    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const response = await list(`?limit=200${cursor === null ? "" : `&cursor=${cursor}`}`);
      expect(response.statusCode).toBe(200);
      const page = response.json() as { agents: { id: string }[]; nextCursor: string | null };
      expect(page.agents.length).toBeLessThanOrEqual(200);
      seen.push(...page.agents.map((a) => a.id));
      cursor = page.nextCursor;
    } while (cursor !== null);

    expect(new Set(seen).size).toBe(seen.length);
    expect([...seen].sort()).toEqual(seen);
    for (const id of mine) expect(seen).toContain(id);
  });

  it("starts a page after the cursor", async () => {
    const a = await registered();
    const page = (await list(`?cursor=${a.id}&limit=5`)).json() as { agents: { id: string }[] };
    expect(page.agents.every((agent) => agent.id > a.id)).toBe(true);
  });

  it.each([
    ["a malformed id", "?id=not-a-uuid"],
    ["a malformed DID", "?did=not-a-did"],
    ["a DID with a newline", `?did=${encodeURIComponent("did:web:x\n")}`],
    ["an id and a DID together", "?id=00000000-0000-4000-8000-000000000000&did=did:web:x"],
    ["a page limit over the maximum", "?limit=201"],
    ["a page limit of 0", "?limit=0"],
    ["a page limit that is not a number", "?limit=ten"],
    ["a malformed cursor", "?cursor=abc"],
    ["an unknown parameter", "?name=billing-bot"],
    ["a repeated parameter", "?limit=1&limit=2"],
  ])("refuses %s with 400 INVALID_INPUT", async (_label, query) => {
    const response = await list(query);
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: { code: "INVALID_INPUT" } });
  });

  it("is not audited: a read changes nothing (ADR 0022 §3)", async () => {
    const events: AuditEvent[] = [];
    const audited = await buildServer({
      auditReporter: { report: (event) => events.push(event) },
      db,
      controlPlaneAuth: readPlane.guard,
      didDomain: DOMAIN,
      issuerKey: issuerKey(),
      statusAllocator: fakeStatusAllocator(),
    });
    const response = await audited.inject({
      method: "GET",
      url: "/agents?limit=1",
      headers: bearer(readKey),
    });
    expect(response.statusCode).toBe(200);
    expect(events).toEqual([]);
  });
});

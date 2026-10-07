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
import { createDb } from "./db/client.js";
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

import { randomUUID } from "node:crypto";
import {
  buildDidWebDocument,
  buildRegistrationRequest,
  buildTokenRequestProof,
  createLocalKeyProvider,
  createLocalSecretCipher,
  generateKeyPair,
  issueCredential,
  ok,
  sign,
  type SignedCredential,
} from "@custos/core";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { storeToolCredential } from "../credentials/store.js";
import { grantToolAccess } from "../policy/policy.js";
import { createDb } from "../db/client.js";
import { issueToolToken } from "./issue.js";
import { createInMemoryReplayCache, type ReplayCache } from "./replay-cache.js";
import { createTrustedIssuer, type TrustedIssuer } from "./trusted-issuer.js";

/** Nobody revoked — the baseline these tests assume. */
const neverRevoked = { isRevoked: () => false };

/** Stands in for the revocation service so registration can succeed here. */
let nextStatusListIndex = 200_000;
const fakeStatusAllocator = {
  allocate: async () =>
    ok({
      statusListIndex: nextStatusListIndex++,
      statusListCredential: "http://127.0.0.1:4503/status/revocation",
    }),
};

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const vaultDb = createDb(databaseUrl);
const identityDb = createIdentityDb(databaseUrl);
const cipher = createLocalSecretCipher(new Uint8Array(32).fill(3));
const ISSUER_SEED = new Uint8Array(32).fill(11);
const TOKENS_URL = "https://vault.custos.example/tokens";
const MAX_SKEW = 60;

const controlPlane = createTestControlPlane(identityDb);
let operatorKey: string;

beforeAll(async () => {
  operatorKey = await controlPlane.key("operator", ["agents:register"]);
});

afterAll(async () => {
  await vaultDb.$client.end();
  await identityDb.$client.end();
});

function identityServer(domain: string, seed: Uint8Array = ISSUER_SEED) {
  return buildIdentityServer({
    db: identityDb,
    controlPlaneAuth: controlPlane.guard,
    didDomain: domain,
    issuerKey: {
      keyProvider: createLocalKeyProvider({ importedKeys: { issuer: seed } }),
      keyId: "issuer",
    },
    statusAllocator: fakeStatusAllocator,
  });
}

interface Registered {
  readonly credential: SignedCredential;
  readonly agentDid: string;
  /** The agent's private key — only the agent has it. */
  readonly secretKey: Uint8Array;
}

async function registerOn(
  app: Awaited<ReturnType<typeof identityServer>>,
  domain: string,
): Promise<Registered> {
  const request = await buildRegistrationRequest({
    audience: `did:web:${encodeURIComponent(domain)}`,
    now: new Date(),
  });
  const response = await app.inject({
    method: "POST",
    url: "/agents",
    headers: bearer(operatorKey),
    payload: request.body,
  });
  const body = response.json() as { credential: SignedCredential; did: string };
  return { credential: body.credential, agentDid: body.did, secretKey: request.secretKey };
}

/**
 * A real identity service listening on `port`, the vault's pinned trusted
 * issuer, and a registered agent. `register` registers further agents.
 */
async function withTrustedIdentity<T>(
  port: number,
  run: (ctx: {
    readonly agent: Registered;
    readonly trustedIssuer: TrustedIssuer;
    readonly domain: string;
    readonly register: () => Promise<Registered>;
  }) => Promise<T>,
): Promise<T> {
  const domain = `127.0.0.1:${port}`;
  const app = await identityServer(domain);
  await app.listen({ port, host: "127.0.0.1" });
  try {
    return await run({
      agent: await registerOn(app, domain),
      trustedIssuer: createTrustedIssuer({ did: `did:web:127.0.0.1%3A${port}` }),
      domain,
      register: () => registerOn(app, domain),
    });
  } finally {
    await app.close();
  }
}

async function vaultSigningKey() {
  const keyProvider = createLocalKeyProvider();
  const { keyId } = await keyProvider.createKeyPair();
  return { keyProvider, signingKeyId: keyId };
}

async function toolWithSecret(): Promise<string> {
  const tool = `test-tool-${randomUUID()}`;
  await storeToolCredential({ db: vaultDb, cipher, tool, secret: "sk_test_x" });
  return tool;
}

/** A valid proof that the caller holds `secretKey`, addressed to this vault's /tokens. */
async function proofCheck(
  secretKey: Uint8Array,
  options: { now?: Date; audience?: string; replayCache?: ReplayCache } = {},
) {
  return {
    proof: await buildTokenRequestProof({
      audience: options.audience ?? TOKENS_URL,
      secretKey,
      now: options.now ?? new Date(),
    }),
    audience: TOKENS_URL,
    maxSkewSeconds: MAX_SKEW,
    replayCache: options.replayCache ?? createInMemoryReplayCache(),
  };
}

function claimsOf(token: string): Record<string, unknown> {
  const [claims] = token.split(".");
  return JSON.parse(Buffer.from(claims ?? "", "base64url").toString("utf8"));
}

/** A granted agent and tool, ready for token requests; `request` defaults to a valid proof. */
async function withGrantedAgent<T>(
  port: number,
  run: (ctx: {
    readonly agent: Registered;
    readonly trustedIssuer: TrustedIssuer;
    readonly tool: string;
    readonly request: (overrides?: {
      proofOfPossession?: Awaited<ReturnType<typeof proofCheck>>;
      revocation?: { isRevoked(did: string): boolean };
      now?: Date;
    }) => ReturnType<typeof issueToolToken>;
  }) => Promise<T>,
): Promise<T> {
  return withTrustedIdentity(port, async ({ agent, trustedIssuer }) => {
    const tool = await toolWithSecret();
    await grantToolAccess(vaultDb, agent.agentDid, tool);
    const signing = await vaultSigningKey();
    return run({
      agent,
      trustedIssuer,
      tool,
      request: async (overrides = {}) =>
        issueToolToken({
          db: vaultDb,
          ...signing,
          agentCredential: agent.credential,
          tool,
          action: "list-customers",
          now: overrides.now ?? new Date(),
          revocation: overrides.revocation ?? neverRevoked,
          trustedIssuer,
          proofOfPossession: overrides.proofOfPossession ?? (await proofCheck(agent.secretKey)),
        }),
    });
  });
}

describe("issueToolToken", () => {
  it("issues a 60s token whose subject is the agent (credentialSubject.id), not the issuer", async () => {
    await withTrustedIdentity(4211, async ({ agent, trustedIssuer }) => {
      const tool = await toolWithSecret();
      await grantToolAccess(vaultDb, agent.agentDid, tool);
      const now = new Date();

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: agent.credential,
        tool,
        action: "list-customers",
        now,
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(agent.secretKey, { now }),
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const iat = Math.floor(now.getTime() / 1000);
      expect(result.value.expiresAt).toBe(new Date((iat + 60) * 1000).toISOString());
      expect(claimsOf(result.value.token).sub).toBe(agent.agentDid);
      expect(claimsOf(result.value.token).sub).not.toBe(trustedIssuer.did);
    });
  });

  it("rejects a request for a tool the vault has no stored credential for", async () => {
    await withTrustedIdentity(4212, async ({ agent, trustedIssuer }) => {
      const unknownTool = `unknown-tool-${randomUUID()}`;

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: agent.credential,
        tool: unknownTool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(agent.secretKey),
      });

      expect(result).toEqual({ ok: false, error: { code: "UNKNOWN_TOOL", tool: unknownTool } });
    });
  });

  it("rejects a verified agent with no policy grant for the tool — deny by default", async () => {
    await withTrustedIdentity(4218, async ({ agent, trustedIssuer }) => {
      const tool = await toolWithSecret();

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: agent.credential,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(agent.secretKey),
      });

      expect(result).toEqual({
        ok: false,
        error: { code: "POLICY_DENIED", agentId: agent.agentDid, tool },
      });
    });
  });

  it("does not treat a grant recorded under the issuer's DID as a grant to any agent", async () => {
    await withTrustedIdentity(4215, async ({ agent, trustedIssuer }) => {
      const tool = await toolWithSecret();
      await grantToolAccess(vaultDb, trustedIssuer.did, tool);

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: agent.credential,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(agent.secretKey),
      });

      expect(result.ok === false && result.error.code).toBe("POLICY_DENIED");
    });
  });

  it("denies a revoked agent — and only that agent, though both share one issuer", async () => {
    await withTrustedIdentity(4216, async ({ agent, trustedIssuer, register }) => {
      const other = await register();
      const tool = await toolWithSecret();
      await grantToolAccess(vaultDb, agent.agentDid, tool);
      await grantToolAccess(vaultDb, other.agentDid, tool);
      const revocation = { isRevoked: (did: string) => did === agent.agentDid };
      const request = async (who: Registered) =>
        issueToolToken({
          db: vaultDb,
          ...(await vaultSigningKey()),
          agentCredential: who.credential,
          tool,
          action: "list-customers",
          now: new Date(),
          revocation,
          trustedIssuer,
          proofOfPossession: await proofCheck(who.secretKey),
        });

      expect(await request(agent)).toEqual({
        ok: false,
        error: { code: "AGENT_REVOKED", agentId: agent.agentDid },
      });
      expect((await request(other)).ok).toBe(true);
    });
  });

  it("rejects an agent credential tampered with after issuance", async () => {
    await withTrustedIdentity(4213, async ({ agent, trustedIssuer }) => {
      const tool = await toolWithSecret();
      const tampered = structuredClone(agent.credential) as SignedCredential & {
        credentialSubject: { id: string };
      };
      tampered.credentialSubject.id = "did:web:attacker.example";

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: tampered,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(agent.secretKey),
      });

      expect(result).toEqual({
        ok: false,
        error: { code: "INVALID_AGENT_CREDENTIAL", reason: "SIGNATURE_INVALID" },
      });
    });
  });

  it("rejects a validly signed credential from an issuer that is not the pinned one", async () => {
    await withTrustedIdentity(4217, async ({ trustedIssuer }) => {
      const tool = await toolWithSecret();
      const otherDomain = "other-identity.custos.example";
      const other = await identityServer(otherDomain, new Uint8Array(32).fill(12));
      const foreign = await registerOn(other, otherDomain);

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: foreign.credential,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(foreign.secretKey),
      });

      expect(result).toEqual({
        ok: false,
        error: { code: "INVALID_AGENT_CREDENTIAL", reason: "UNTRUSTED_ISSUER" },
      });
    });
  });

  it("rejects a self-issued credential — anyone with a keypair and a domain can make one", async () => {
    await withTrustedIdentity(4219, async ({ trustedIssuer }) => {
      const tool = await toolWithSecret();
      const { publicKey, secretKey } = generateKeyPair();
      const self = buildDidWebDocument({ domain: "self.example", publicKey });
      const issued = await issueCredential({
        unsignedCredential: {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          id: "urn:uuid:self",
          type: ["VerifiableCredential"],
          issuer: self.id,
          validFrom: new Date().toISOString(),
          credentialSubject: { id: self.id },
        },
        signer: {
          id: self.verificationMethod[0].id,
          sign: async ({ data }) => sign(data, secretKey),
        },
      });
      if (!issued.ok) throw new Error("setup");

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: issued.value,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(secretKey),
      });

      expect(result).toEqual({
        ok: false,
        error: { code: "INVALID_AGENT_CREDENTIAL", reason: "UNTRUSTED_ISSUER" },
      });
    });
  });

  it("rejects a forgery that names the trusted issuer but is signed with another key", async () => {
    await withTrustedIdentity(4220, async ({ trustedIssuer, domain }) => {
      const tool = await toolWithSecret();
      // Same did:web domain as the real issuer, different key: the credential
      // claims the trusted DID but its signature can't match the published key.
      const forger = await identityServer(domain, new Uint8Array(32).fill(13));
      const forged = await registerOn(forger, domain);
      expect(forged.credential.issuer).toBe(trustedIssuer.did);

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: forged.credential,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(forged.secretKey),
      });

      expect(result.ok === false && result.error.code).toBe("INVALID_AGENT_CREDENTIAL");
    });
  });

  it.each([
    ["no subject", { name: "nobody" }, "MISSING_SUBJECT"],
    ["no embedded agent key", { id: "did:web:x:agents:no-key" }, "MISSING_AGENT_KEY"],
  ])("rejects a trusted-issuer credential with %s", async (_label, credentialSubject, reason) => {
    await withTrustedIdentity(4221, async ({ trustedIssuer, domain }) => {
      const tool = await toolWithSecret();
      const keyProvider = createLocalKeyProvider({ importedKeys: { issuer: ISSUER_SEED } });
      const issuerDoc = buildDidWebDocument({
        domain,
        publicKey: await keyProvider.getPublicKey("issuer"),
      });
      const issued = await issueCredential({
        unsignedCredential: {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          id: `urn:uuid:${randomUUID()}`,
          type: ["VerifiableCredential"],
          issuer: issuerDoc.id,
          validFrom: new Date().toISOString(),
          credentialSubject,
        },
        signer: {
          id: issuerDoc.verificationMethod[0].id,
          sign: ({ data }) => keyProvider.sign("issuer", data),
        },
      });
      if (!issued.ok) throw new Error(`setup: ${issued.error.reason}`);

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: issued.value,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(generateKeyPair().secretKey),
      });

      expect(result).toEqual({ ok: false, error: { code: "INVALID_AGENT_CREDENTIAL", reason } });
    });
  });

  it("rejects every credential while the trusted issuer's DID document can't be resolved", async () => {
    const tool = await toolWithSecret();
    const unreachable = createTrustedIssuer({ did: "did:web:localhost%3A1" });
    const credential = {
      issuer: "did:web:localhost%3A1",
      credentialSubject: { id: "did:web:localhost%3A1:agents:x" },
    } as unknown as SignedCredential;

    const result = await issueToolToken({
      db: vaultDb,
      ...(await vaultSigningKey()),
      agentCredential: credential,
      tool,
      action: "list-customers",
      now: new Date(),
      revocation: neverRevoked,
      trustedIssuer: unreachable,
      proofOfPossession: await proofCheck(generateKeyPair().secretKey),
    });

    expect(result.ok === false && result.error.code).toBe("INVALID_AGENT_CREDENTIAL");
  });

  it("surfaces a signing failure (e.g. the KMS is unreachable) as an error value", async () => {
    await withTrustedIdentity(4214, async ({ agent, trustedIssuer }) => {
      const tool = await toolWithSecret();
      await grantToolAccess(vaultDb, agent.agentDid, tool);
      const failingKeyProvider = {
        createKeyPair: () => Promise.reject(new Error("unreachable")),
        sign: () => Promise.reject(new Error("kms unreachable")),
        getPublicKey: () => Promise.reject(new Error("unreachable")),
      };

      const result = await issueToolToken({
        db: vaultDb,
        keyProvider: failingKeyProvider,
        signingKeyId: "irrelevant",
        agentCredential: agent.credential,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
        trustedIssuer,
        proofOfPossession: await proofCheck(agent.secretKey),
      });

      expect(result).toEqual({
        ok: false,
        error: { code: "SIGNING_FAILED", reason: "kms unreachable" },
      });
    });
  });
});

describe("issueToolToken proof of possession (ADR 0007 decision 3)", () => {
  it("refuses a copied credential presented without the agent's private key", async () => {
    await withGrantedAgent(4222, async ({ request }) => {
      const thief = generateKeyPair();

      const result = await request({ proofOfPossession: await proofCheck(thief.secretKey) });

      expect(result).toEqual({
        ok: false,
        error: { code: "INVALID_PROOF_OF_POSSESSION", reason: "SIGNATURE_INVALID" },
      });
    });
  });

  it("refuses a replayed proof", async () => {
    await withGrantedAgent(4223, async ({ agent, request }) => {
      const replayCache = createInMemoryReplayCache();
      const once = await proofCheck(agent.secretKey, { replayCache });

      expect((await request({ proofOfPossession: once })).ok).toBe(true);
      expect(await request({ proofOfPossession: once })).toEqual({
        ok: false,
        error: { code: "INVALID_PROOF_OF_POSSESSION", reason: "REPLAYED" },
      });
    });
  });

  it("accepts a fresh proof for every request", async () => {
    await withGrantedAgent(4224, async ({ agent, request }) => {
      const replayCache = createInMemoryReplayCache();

      expect(
        (await request({ proofOfPossession: await proofCheck(agent.secretKey, { replayCache }) }))
          .ok,
      ).toBe(true);
      expect(
        (await request({ proofOfPossession: await proofCheck(agent.secretKey, { replayCache }) }))
          .ok,
      ).toBe(true);
    });
  });

  it("refuses a proof addressed to a different vault", async () => {
    await withGrantedAgent(4225, async ({ agent, request }) => {
      const result = await request({
        proofOfPossession: await proofCheck(agent.secretKey, {
          audience: "https://other-vault.example/tokens",
        }),
      });

      expect(result.ok === false && result.error).toEqual({
        code: "INVALID_PROOF_OF_POSSESSION",
        reason: "WRONG_AUDIENCE",
      });
    });
  });

  it("refuses a stale proof", async () => {
    await withGrantedAgent(4226, async ({ agent, request }) => {
      const result = await request({
        proofOfPossession: await proofCheck(agent.secretKey, {
          now: new Date(Date.now() - 5 * 60_000),
        }),
      });

      expect(result.ok === false && result.error).toEqual({
        code: "INVALID_PROOF_OF_POSSESSION",
        reason: "STALE",
      });
    });
  });

  it("refuses a registration proof presented as a token-request proof", async () => {
    await withGrantedAgent(4227, async ({ agent, request }) => {
      const { issuePossessionProof, REGISTRATION_PROOF_TYPE } = await import("@custos/core");
      const registrationProof = await issuePossessionProof({
        claims: {
          typ: REGISTRATION_PROOF_TYPE,
          aud: TOKENS_URL,
          iat: Math.floor(Date.now() / 1000),
          jti: randomUUID(),
        },
        sign: async (data) => sign(data, agent.secretKey),
      });
      if (!registrationProof.ok) throw new Error("setup");

      const result = await request({
        proofOfPossession: {
          proof: registrationProof.value,
          audience: TOKENS_URL,
          maxSkewSeconds: MAX_SKEW,
          replayCache: createInMemoryReplayCache(),
        },
      });

      expect(result.ok === false && result.error).toEqual({
        code: "INVALID_PROOF_OF_POSSESSION",
        reason: "WRONG_TYPE",
      });
    });
  });

  it("checks possession before revocation — an impostor learns nothing about the agent's status", async () => {
    await withGrantedAgent(4228, async ({ agent, request }) => {
      const result = await request({
        proofOfPossession: await proofCheck(generateKeyPair().secretKey),
        revocation: { isRevoked: (did) => did === agent.agentDid },
      });

      expect(result.ok === false && result.error.code).toBe("INVALID_PROOF_OF_POSSESSION");
    });
  });

  it("fails closed when the replay cache is full", async () => {
    await withGrantedAgent(4229, async ({ agent, request }) => {
      const full: ReplayCache = { record: () => "full" };

      const result = await request({
        proofOfPossession: await proofCheck(agent.secretKey, { replayCache: full }),
      });

      expect(result.ok === false && result.error).toEqual({
        code: "INVALID_PROOF_OF_POSSESSION",
        reason: "REPLAY_CACHE_FULL",
      });
    });
  });
});

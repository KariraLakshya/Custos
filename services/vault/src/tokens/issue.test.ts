import { randomUUID } from "node:crypto";
import {
  buildDidWebDocument,
  buildRegistrationRequest,
  createLocalKeyProvider,
  createLocalSecretCipher,
  generateKeyPair,
  issueCredential,
  ok,
  sign,
  type SignedCredential,
} from "@custos/core";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import { afterAll, describe, expect, it } from "vitest";
import { storeToolCredential } from "../credentials/store.js";
import { grantToolAccess } from "../policy/policy.js";
import { createDb } from "../db/client.js";
import { issueToolToken } from "./issue.js";
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

afterAll(async () => {
  await vaultDb.$client.end();
  await identityDb.$client.end();
});

function identityServer(domain: string, seed: Uint8Array = ISSUER_SEED) {
  return buildIdentityServer({
    db: identityDb,
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
}

async function registerOn(
  app: Awaited<ReturnType<typeof identityServer>>,
  domain: string,
): Promise<Registered> {
  const request = await buildRegistrationRequest({
    audience: `did:web:${encodeURIComponent(domain)}`,
    now: new Date(),
  });
  const response = await app.inject({ method: "POST", url: "/agents", payload: request.body });
  const body = response.json() as { credential: SignedCredential; did: string };
  return { credential: body.credential, agentDid: body.did };
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

function claimsOf(token: string): Record<string, unknown> {
  const [claims] = token.split(".");
  return JSON.parse(Buffer.from(claims ?? "", "base64url").toString("utf8"));
}

describe("issueToolToken", () => {
  it("issues a 60s token whose subject is the agent (credentialSubject.id), not the issuer", async () => {
    await withTrustedIdentity(4211, async ({ agent, trustedIssuer }) => {
      const tool = await toolWithSecret();
      await grantToolAccess(vaultDb, agent.agentDid, tool);
      const now = new Date("2026-01-01T00:00:00Z");

      const result = await issueToolToken({
        db: vaultDb,
        ...(await vaultSigningKey()),
        agentCredential: agent.credential,
        tool,
        action: "list-customers",
        now,
        revocation: neverRevoked,
        trustedIssuer,
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.expiresAt).toBe("2026-01-01T00:01:00.000Z");
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
      const request = async (credential: SignedCredential) =>
        issueToolToken({
          db: vaultDb,
          ...(await vaultSigningKey()),
          agentCredential: credential,
          tool,
          action: "list-customers",
          now: new Date(),
          revocation,
          trustedIssuer,
        });

      expect(await request(agent.credential)).toEqual({
        ok: false,
        error: { code: "AGENT_REVOKED", agentId: agent.agentDid },
      });
      expect((await request(other.credential)).ok).toBe(true);
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
      });

      expect(result.ok === false && result.error.code).toBe("INVALID_AGENT_CREDENTIAL");
    });
  });

  it("rejects a trusted-issuer credential with no subject", async () => {
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
          id: "urn:uuid:no-subject",
          type: ["VerifiableCredential"],
          issuer: issuerDoc.id,
          validFrom: new Date().toISOString(),
          credentialSubject: { name: "nobody" },
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
      });

      expect(result).toEqual({
        ok: false,
        error: { code: "INVALID_AGENT_CREDENTIAL", reason: "MISSING_SUBJECT" },
      });
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
      });

      expect(result).toEqual({
        ok: false,
        error: { code: "SIGNING_FAILED", reason: "kms unreachable" },
      });
    });
  });
});

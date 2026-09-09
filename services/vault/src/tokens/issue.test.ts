import { randomUUID } from "node:crypto";
import {
  createLocalKeyProvider,
  createLocalSecretCipher,
  ok,
  type SignedCredential,
} from "@custos/core";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import type { FastifyInstance } from "fastify";
import { afterAll, describe, expect, it } from "vitest";
import { storeToolCredential } from "../credentials/store.js";
import { createDb } from "../db/client.js";
import { issueToolToken } from "./issue.js";

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

afterAll(async () => {
  await vaultDb.$client.end();
  await identityDb.$client.end();
});

async function withRegisteredAgent<T>(
  port: number,
  run: (credential: SignedCredential) => Promise<T>,
): Promise<T> {
  const app: FastifyInstance = buildIdentityServer({
    db: identityDb,
    didDomain: `127.0.0.1:${port}`,
    statusAllocator: fakeStatusAllocator,
  });
  await app.listen({ port, host: "127.0.0.1" });
  try {
    const response = await fetch(`http://127.0.0.1:${port}/agents`, { method: "POST" });
    const { credential } = (await response.json()) as { credential: SignedCredential };
    return await run(credential);
  } finally {
    await app.close();
  }
}

describe("issueToolToken", () => {
  it("issues a 60s-scoped token for a verified agent and a known tool", async () => {
    await withRegisteredAgent(4201, async (credential) => {
      const tool = `test-tool-${randomUUID()}`;
      await storeToolCredential({ db: vaultDb, cipher, tool, secret: "sk_test_x" });
      const keyProvider = createLocalKeyProvider();
      const { keyId } = await keyProvider.createKeyPair();
      const now = new Date("2026-01-01T00:00:00Z");

      const result = await issueToolToken({
        db: vaultDb,
        keyProvider,
        signingKeyId: keyId,
        agentCredential: credential,
        tool,
        action: "list-customers",
        now,
        revocation: neverRevoked,
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.token.split(".")).toHaveLength(2);
        expect(result.value.expiresAt).toBe("2026-01-01T00:01:00.000Z");
      }
    });
  });

  it("rejects a request for a tool the vault has no stored credential for", async () => {
    await withRegisteredAgent(4202, async (credential) => {
      const keyProvider = createLocalKeyProvider();
      const { keyId } = await keyProvider.createKeyPair();
      const unknownTool = `unknown-tool-${randomUUID()}`;

      const result = await issueToolToken({
        db: vaultDb,
        keyProvider,
        signingKeyId: keyId,
        agentCredential: credential,
        tool: unknownTool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
      });

      expect(result).toEqual({ ok: false, error: { code: "UNKNOWN_TOOL", tool: unknownTool } });
    });
  });

  it("rejects an agent credential tampered with after issuance", async () => {
    await withRegisteredAgent(4203, async (credential) => {
      const tool = `test-tool-${randomUUID()}`;
      await storeToolCredential({ db: vaultDb, cipher, tool, secret: "sk_test_x" });
      const tampered = structuredClone(credential) as SignedCredential & {
        credentialSubject: { id: string };
      };
      tampered.credentialSubject.id = "did:web:attacker.example";
      const keyProvider = createLocalKeyProvider();
      const { keyId } = await keyProvider.createKeyPair();

      const result = await issueToolToken({
        db: vaultDb,
        keyProvider,
        signingKeyId: keyId,
        agentCredential: tampered,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
      });

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("INVALID_AGENT_CREDENTIAL");
    });
  });

  it("rejects a credential whose issuer DID cannot be resolved", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db: vaultDb, cipher, tool, secret: "sk_test_x" });
    const keyProvider = createLocalKeyProvider();
    const { keyId } = await keyProvider.createKeyPair();

    const unresolvableCredential = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:nonexistent",
      type: ["VerifiableCredential"],
      issuer: "did:web:localhost%3A1:agents:nonexistent",
      validFrom: new Date().toISOString(),
      credentialSubject: { id: "did:web:localhost%3A1:agents:nonexistent" },
      proof: {
        type: "Ed25519Signature2020",
        created: new Date().toISOString(),
        verificationMethod: "did:web:localhost%3A1:agents:nonexistent#zFake",
        proofPurpose: "assertionMethod",
        proofValue: "z" + "1".repeat(88),
      },
    } as unknown as SignedCredential;

    const result = await issueToolToken({
      db: vaultDb,
      keyProvider,
      signingKeyId: keyId,
      agentCredential: unresolvableCredential,
      tool,
      action: "list-customers",
      now: new Date(),
      revocation: neverRevoked,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("INVALID_AGENT_CREDENTIAL");
  });

  it("surfaces a signing failure (e.g. the KMS is unreachable) as an error value", async () => {
    await withRegisteredAgent(4204, async (credential) => {
      const tool = `test-tool-${randomUUID()}`;
      await storeToolCredential({ db: vaultDb, cipher, tool, secret: "sk_test_x" });
      const failingKeyProvider = {
        createKeyPair: () => Promise.reject(new Error("unreachable")),
        sign: () => Promise.reject(new Error("kms unreachable")),
      };

      const result = await issueToolToken({
        db: vaultDb,
        keyProvider: failingKeyProvider,
        signingKeyId: "irrelevant",
        agentCredential: credential,
        tool,
        action: "list-customers",
        now: new Date(),
        revocation: neverRevoked,
      });

      expect(result).toEqual({
        ok: false,
        error: { code: "SIGNING_FAILED", reason: "kms unreachable" },
      });
    });
  });
});

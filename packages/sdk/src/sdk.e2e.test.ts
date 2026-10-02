import { createMockDatabaseConnector, createMockSlackConnector } from "@custos/connectors";
import { createLocalKeyProvider, createLocalSecretCipher } from "@custos/core";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import {
  buildServer as buildRevocationServer,
  createDb as createRevocationDb,
} from "@custos/revocation";
import { buildServer as buildVaultServer, createDb as createVaultDb } from "@custos/vault";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createCustos, type Agent } from "./index.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const identityDb = createIdentityDb(databaseUrl);
const revocationDb = createRevocationDb(databaseUrl);
const vaultDb = createVaultDb(databaseUrl);

// Real keys in the real api_keys table, as `custos-admin dev-keys` makes them.
const controlPlane = createTestControlPlane(identityDb);
let operatorKey: string;
let identityServiceKey: string;
let revocationServiceKey: string;
let vaultServiceKey: string;

beforeAll(async () => {
  operatorKey = await controlPlane.key("operator", [
    "credentials:write",
    "policies:write",
    "agents:revoke",
    "agents:register",
  ]);
  identityServiceKey = await controlPlane.key("service", ["status:allocate", "audit:write"]);
  revocationServiceKey = await controlPlane.key("service", ["audit:write"]);
  vaultServiceKey = await controlPlane.key("service", ["audit:write"]);
});

afterAll(async () => {
  await identityDb.$client.end();
  await revocationDb.$client.end();
  await vaultDb.$client.end();
});

// Each stack gets its own ports. Reusing one set across stacks let a new
// vault's first revocation sync reuse a pooled keep-alive connection to the
// previous, closed revocation service — the sync failed, and the vault
// (correctly) failed closed with REVOCATION_STATE_STALE.
let nextPortBase = 5601;

/**
 * Real identity, revocation, and vault services wired as in production —
 * identity reserves a status list index on the real revocation service, and a
 * deprovision genuinely pushes a tombstone into the vault's revocation cache.
 */
async function withStack<T>(
  run: (urls: { identityUrl: string; revocationUrl: string; vaultUrl: string }) => Promise<T>,
): Promise<T> {
  const base = nextPortBase;
  nextPortBase += 3;
  const ports = { identity: base, revocation: base + 1, vault: base + 2 } as const;
  const identityUrl = `http://127.0.0.1:${ports.identity}`;
  const revocationUrl = `http://127.0.0.1:${ports.revocation}`;
  const vaultUrl = `http://127.0.0.1:${ports.vault}`;

  const revocationApp = await buildRevocationServer({
    db: revocationDb,
    controlPlaneAuth: controlPlane.guard,
    serviceKey: revocationServiceKey,
    didDomain: `127.0.0.1:${ports.revocation}`,
    subscriberUrls: [vaultUrl],
  });
  await revocationApp.listen({ port: ports.revocation, host: "127.0.0.1" });

  const identityApp = await buildIdentityServer({
    db: identityDb,
    controlPlaneAuth: controlPlane.guard,
    serviceKey: identityServiceKey,
    didDomain: `127.0.0.1:${ports.identity}`,
    issuerKey: {
      keyProvider: createLocalKeyProvider({
        importedKeys: { issuer: new Uint8Array(32).fill(31) },
      }),
      keyId: "issuer",
    },
    revocationUrl,
  });
  await identityApp.listen({ port: ports.identity, host: "127.0.0.1" });

  const vaultApp = await buildVaultServer({
    db: vaultDb,
    controlPlaneAuth: controlPlane.guard,
    serviceKey: vaultServiceKey,
    cipher: createLocalSecretCipher(new Uint8Array(32).fill(21)),
    connectors: [createMockDatabaseConnector(), createMockSlackConnector()],
    revocationUrl,
    revocationIssuerDid: `did:web:127.0.0.1%3A${ports.revocation}`,
    trustedIssuerDid: `did:web:127.0.0.1%3A${ports.identity}`,
    publicUrl: vaultUrl,
    revocationResyncIntervalMs: 5_000,
  });
  await vaultApp.listen({ port: ports.vault, host: "127.0.0.1" });

  try {
    return await run({ identityUrl, revocationUrl, vaultUrl });
  } finally {
    await vaultApp.close();
    await identityApp.close();
    await revocationApp.close();
  }
}

/** Operator setup the SDK deliberately doesn't cover: the vault holds the real tool secret. */
async function storeToolSecret(vaultUrl: string, tool: string): Promise<void> {
  const response = await fetch(new URL("/credentials", vaultUrl), {
    method: "POST",
    headers: { "content-type": "application/json", ...bearer(operatorKey) },
    body: JSON.stringify({ tool, secret: "unused-by-the-mock" }),
  });
  expect(response.ok).toBe(true);
}

describe("@custos/sdk end to end: register → connect → deprovision", () => {
  it("runs one agent's full lifecycle through the SDK alone", async () => {
    await withStack(async ({ identityUrl, revocationUrl, vaultUrl }) => {
      await storeToolSecret(vaultUrl, "mock-database");
      await storeToolSecret(vaultUrl, "mock-slack");
      const custos = createCustos({ identityUrl, revocationUrl, vaultUrl, operatorKey });

      const registered = await custos.register();
      // The agent's own process only ever needs this plain data.
      const agent = JSON.parse(JSON.stringify(registered)) as Agent;
      const database = custos.connect(agent, "mock-database");
      const slack = custos.connect(agent, "mock-slack");

      // Deny by default: registered is not the same as permitted.
      const beforeGrant = await database.call("query", { table: "customers" });
      expect(beforeGrant.ok === false && beforeGrant.error).toMatchObject({
        stage: "token",
        status: 403,
        code: "POLICY_DENIED",
      });

      await custos.grant(agent, "mock-database");
      const allowed = await database.call("query", { table: "customers" });
      expect(allowed.ok).toBe(true);
      if (allowed.ok) expect(allowed.value).toHaveLength(2);

      // The grant is per tool: slack is still outside the allowlist.
      const ungranted = await slack.call("post-message", { channel: "#ops", text: "hi" });
      expect(ungranted.ok === false && ungranted.error.code).toBe("POLICY_DENIED");

      const revokedAt = Date.now();
      const deprovisioned = await custos.deprovision(agent, { reason: "sdk e2e" });
      expect(deprovisioned).toMatchObject({ agentId: agent.id, alreadyRevoked: false });
      expect(deprovisioned.broadcast.delivered).toBe(1);

      const afterRevoke = await database.call("query", { table: "customers" });
      expect(Date.now() - revokedAt).toBeLessThan(1_000);
      expect(afterRevoke.ok === false && afterRevoke.error).toMatchObject({
        stage: "token",
        status: 403,
        code: "AGENT_REVOKED",
      });
    });
  });

  it("gives a copied credential nothing without the agent's private key (ADR 0007)", async () => {
    await withStack(async ({ identityUrl, revocationUrl, vaultUrl }) => {
      await storeToolSecret(vaultUrl, "mock-database");
      const custos = createCustos({ identityUrl, revocationUrl, vaultUrl, operatorKey });
      const agent = await custos.register();
      await custos.grant(agent, "mock-database");

      // The thief has agent.json, but their own key — not the agent's.
      const thief = { ...agent, secretKey: "22".repeat(32) };
      const stolen = await custos.connect(thief, "mock-database").call("query", {
        table: "customers",
      });
      const genuine = await custos.connect(agent, "mock-database").call("query", {
        table: "customers",
      });

      expect(stolen.ok === false && stolen.error).toMatchObject({
        stage: "token",
        status: 401,
        code: "INVALID_PROOF_OF_POSSESSION",
      });
      expect(genuine.ok).toBe(true);
    });
  });

  it("rejects a tampered credential at token issuance", async () => {
    await withStack(async ({ identityUrl, revocationUrl, vaultUrl }) => {
      await storeToolSecret(vaultUrl, "mock-database");
      const custos = createCustos({ identityUrl, revocationUrl, vaultUrl, operatorKey });
      const agent = await custos.register();
      await custos.grant(agent, "mock-database");

      const tamperedCredential = {
        ...agent.credential,
        credentialSubject: { id: "did:web:attacker.example" },
      };
      const tampered: Agent = { ...agent, credential: tamperedCredential };

      const outcome = await custos.connect(tampered, "mock-database").call("query", {
        table: "customers",
      });
      expect(outcome.ok === false && outcome.error).toMatchObject({
        stage: "token",
        status: 401,
        code: "INVALID_AGENT_CREDENTIAL",
      });
    });
  });
});

describe("@custos/sdk end to end: operator key required (ADR 0008)", () => {
  it("can't register, grant or deprovision with a wrong or unscoped key; an agent's calls need none", async () => {
    await withStack(async ({ identityUrl, revocationUrl, vaultUrl }) => {
      await storeToolSecret(vaultUrl, "mock-database");
      const operator = createCustos({ identityUrl, revocationUrl, vaultUrl, operatorKey });
      const agent = await operator.register();

      const revokeOnly = await controlPlane.key("operator", ["agents:revoke"]);
      const unscoped = createCustos({
        identityUrl,
        revocationUrl,
        vaultUrl,
        operatorKey: revokeOnly,
      });
      await expect(unscoped.register()).rejects.toThrow(
        /register failed: identity service returned 401/,
      );
      await expect(unscoped.grant(agent, "mock-database")).rejects.toThrow(
        /grant failed: vault returned 401/,
      );

      const forged = [
        "custos",
        "operator",
        agent.id.replace(/-/g, "").slice(0, 16),
        "A".repeat(43),
      ].join("_");
      const impostor = createCustos({ identityUrl, revocationUrl, vaultUrl, operatorKey: forged });
      await expect(impostor.deprovision(agent)).rejects.toThrow(
        /deprovision failed: revocation service returned 401/,
      );

      // The agent's own process holds no operator key at all.
      await operator.grant(agent, "mock-database");
      const agentOnly = createCustos({ identityUrl, revocationUrl, vaultUrl });
      const result = await agentOnly
        .connect(agent, "mock-database")
        .call("query", { table: "customers" });
      expect(result.ok).toBe(true);
    });
  });
});

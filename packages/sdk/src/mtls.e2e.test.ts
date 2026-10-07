import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildServer as buildAuditServer, createDb as createAuditDb } from "@custos/audit";
import { createMockDatabaseConnector } from "@custos/connectors";
import {
  createEnvoyOnlyTlsListener,
  createMtlsFetch,
  loadMtlsIdentity,
  serviceUri,
  type EnvoyOnlyTlsListener,
  type MtlsIdentity,
} from "@custos/control-plane-auth";
import {
  createLocalKeyProvider,
  createLocalSecretCipher,
  multibaseToPublicKey,
  verifyAuditRecord,
  type AuditRecord,
  type DidWebDocument,
} from "@custos/core";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import {
  buildServer as buildRevocationServer,
  createDb as createRevocationDb,
} from "@custos/revocation";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { buildServer as buildVaultServer, createDb as createVaultDb } from "@custos/vault";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createCustos } from "./index.js";

/**
 * ADR 0009 end to end: the real identity, revocation, vault and audit
 * services behind the real Envoy, with **no service API keys at all**.
 * Every service-to-service call (identity reserving a revocation slot,
 * every service writing audit records) can only succeed through Envoy with
 * the calling service's certificate. Operators still use API keys (SSO
 * comes later). Needs Docker, like the other mTLS tests.
 */

const repoRoot = resolve(__dirname, "../../..");
const mtlsDir = join(repoRoot, "infra/mtls");
const images = JSON.parse(readFileSync(join(mtlsDir, "images.json"), "utf8")) as { envoy: string };

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const identityDb = createIdentityDb(databaseUrl);
const revocationDb = createRevocationDb(databaseUrl);
const vaultDb = createVaultDb(databaseUrl);
const auditDb = createAuditDb(databaseUrl);
const controlPlane = createTestControlPlane(identityDb);

const PORT = {
  identity: 5701,
  revocation: 5702,
  vault: 5703,
  audit: 5704,
  revocationTls: 5705,
  auditTls: 5706,
  envoyRevocation: 5707,
  envoyAudit: 5708,
} as const;
const url = (port: number) => `http://127.0.0.1:${port}`;
const envoyUrl = (port: number) => `https://localhost:${port}`;
const CONTAINER = "custos-envoy-e2e";

let dir: string;
let operatorKey: string;
const apps: FastifyInstance[] = [];
const listeners: EnvoyOnlyTlsListener[] = [];

function identityFor(name: string, expectedUri?: string): MtlsIdentity {
  const loaded = loadMtlsIdentity(
    {
      certFile: join(dir, `${name}.crt`),
      keyFile: join(dir, `${name}.key`),
      caFile: join(dir, "ca.crt"),
    },
    { now: new Date(), ...(expectedUri ? { expectedUri } : {}) },
  );
  if (!loaded.ok) throw new Error(loaded.error);
  return loaded.value;
}

const asService = (service: string) => createMtlsFetch(identityFor(service, serviceUri(service)));

/** Starts an app on its plain port, and its Envoy-only TLS listener if given one. */
async function start(
  app: FastifyInstance,
  port: number,
  tls?: { listener: EnvoyOnlyTlsListener; port: number },
) {
  apps.push(app);
  await app.listen({ port, host: "127.0.0.1" });
  if (tls) {
    listeners.push(tls.listener);
    // All interfaces: Envoy reaches it from inside Docker.
    await tls.listener.listen(tls.port, "::");
  }
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "custos-mtls-e2e-"));
  execFileSync("node", [join(mtlsDir, "certs.mjs"), dir]);
  operatorKey = await controlPlane.key("operator", [
    "credentials:write",
    "policies:write",
    "agents:revoke",
    "agents:register",
  ]);

  const auditTls = createEnvoyOnlyTlsListener(identityFor("audit-server"));
  await start(
    await buildAuditServer({
      db: auditDb,
      controlPlaneAuth: controlPlane.guard,
      didDomain: `127.0.0.1:${PORT.audit}`,
      serverFactory: auditTls.serverFactory,
    }),
    PORT.audit,
    { listener: auditTls, port: PORT.auditTls },
  );

  const revocationTls = createEnvoyOnlyTlsListener(identityFor("revocation-server"));
  await start(
    await buildRevocationServer({
      db: revocationDb,
      controlPlaneAuth: controlPlane.guard,
      didDomain: `127.0.0.1:${PORT.revocation}`,
      subscriberUrls: [url(PORT.vault)],
      auditUrl: envoyUrl(PORT.envoyAudit),
      mtlsFetch: asService("revocation"),
      serverFactory: revocationTls.serverFactory,
    }),
    PORT.revocation,
    { listener: revocationTls, port: PORT.revocationTls },
  );

  await start(
    await buildIdentityServer({
      db: identityDb,
      controlPlaneAuth: controlPlane.guard,
      didDomain: `127.0.0.1:${PORT.identity}`,
      issuerKey: {
        keyProvider: createLocalKeyProvider({
          importedKeys: { issuer: new Uint8Array(32).fill(51) },
        }),
        keyId: "issuer",
      },
      // Both through Envoy, with identity's certificate.
      revocationUrl: envoyUrl(PORT.envoyRevocation),
      auditUrl: envoyUrl(PORT.envoyAudit),
      mtlsFetch: asService("identity"),
    }),
    PORT.identity,
  );

  await start(
    await buildVaultServer({
      db: vaultDb,
      controlPlaneAuth: controlPlane.guard,
      cipher: createLocalSecretCipher(new Uint8Array(32).fill(61)),
      connectors: [createMockDatabaseConnector()],
      revocationUrl: url(PORT.revocation),
      revocationIssuerDid: `did:web:127.0.0.1%3A${PORT.revocation}`,
      trustedIssuerDid: `did:web:127.0.0.1%3A${PORT.identity}`,
      publicUrl: url(PORT.vault),
      revocationResyncIntervalMs: 5_000,
      auditUrl: envoyUrl(PORT.envoyAudit),
      mtlsFetch: asService("vault"),
    }),
    PORT.vault,
  );

  execFileSync("node", [
    join(mtlsDir, "render-envoy.mjs"),
    join(dir, "envoy.yaml"),
    "--set",
    `REVOCATION_LISTEN_PORT=${PORT.envoyRevocation}`,
    "--set",
    `AUDIT_LISTEN_PORT=${PORT.envoyAudit}`,
    "--set",
    `REVOCATION_UPSTREAM_PORT=${PORT.revocationTls}`,
    "--set",
    `AUDIT_UPSTREAM_PORT=${PORT.auditTls}`,
  ]);
  const user =
    typeof process.getuid === "function"
      ? ["--user", `${process.getuid()}:${process.getgid?.()}`]
      : [];
  execFileSync("docker", ["rm", "-f", CONTAINER], { stdio: "ignore" });
  execFileSync("docker", [
    "run",
    "-d",
    "--rm",
    "--name",
    CONTAINER,
    ...user,
    "--add-host",
    "host.docker.internal:host-gateway",
    "-p",
    `${PORT.envoyRevocation}:${PORT.envoyRevocation}`,
    "-p",
    `${PORT.envoyAudit}:${PORT.envoyAudit}`,
    "-v",
    `${dir}:/etc/custos-mtls:ro`,
    "-v",
    `${join(dir, "envoy.yaml")}:/etc/envoy/envoy.yaml:ro`,
    images.envoy,
    "envoy",
    "-c",
    "/etc/envoy/envoy.yaml",
  ]);

  // Ready once Envoy forwards the vault's certificate through to audit.
  const vaultFetch = asService("vault");
  for (let attempt = 0; ; attempt += 1) {
    const status = await vaultFetch(`${envoyUrl(PORT.envoyAudit)}/health`).then(
      (response) => response.status,
      () => 0,
    );
    if (status === 200) break;
    if (attempt >= 60) throw new Error(`Envoy never became ready (${status})`);
    await new Promise((done) => setTimeout(done, 500));
  }
}, 240_000);

afterAll(async () => {
  execFileSync("docker", ["rm", "-f", CONTAINER], { stdio: "ignore" });
  for (const listener of listeners) await listener.close();
  for (const app of apps.reverse()) await app.close();
  await Promise.all([identityDb, revocationDb, vaultDb, auditDb].map((db) => db.$client.end()));
  if (dir) rmSync(dir, { recursive: true, force: true });
});

async function verifiedRecords(agentDid: string): Promise<AuditRecord[]> {
  const did = (await (
    await fetch(`${url(PORT.audit)}/.well-known/did.json`)
  ).json()) as DidWebDocument;
  const publicKey = multibaseToPublicKey(did.verificationMethod[0].publicKeyMultibase);
  if (!publicKey.ok) throw new Error("bad audit DID document");
  const response = await fetch(
    `${url(PORT.audit)}/records?agentId=${encodeURIComponent(agentDid)}`,
  );
  const { records } = (await response.json()) as { records: string[] };
  return records.map((record) => {
    const verified = verifyAuditRecord({ record, publicKey: publicKey.value });
    if (!verified.ok) throw new Error(`record failed verification: ${verified.error.code}`);
    return verified.value;
  });
}

describe("mTLS end to end: services authenticate to each other only with certificates (ADR 0009)", () => {
  it("runs an agent's lifecycle with no service keys, and the audit log names each service by certificate", async () => {
    const seeded = await fetch(`${url(PORT.vault)}/credentials`, {
      method: "POST",
      headers: { "content-type": "application/json", ...bearer(operatorKey) },
      body: JSON.stringify({ tool: "mock-database", secret: "unused-by-the-mock" }),
    });
    expect(seeded.status).toBe(201);

    const custos = createCustos({
      identityUrl: url(PORT.identity),
      revocationUrl: url(PORT.revocation),
      vaultUrl: url(PORT.vault),
      operatorKey,
    });
    // Registration only works if identity reached revocation through Envoy.
    const agent = await custos.register();
    await custos.grant(agent, "mock-database");
    const call = await custos.connect(agent, "mock-database").call("query", { table: "customers" });
    expect(call.ok).toBe(true);
    await custos.deprovision(agent, { reason: "compromised" });

    let records: AuditRecord[] = [];
    for (let attempt = 0; records.length < 5 && attempt < 40; attempt += 1) {
      await new Promise((done) => setTimeout(done, 100));
      records = await verifiedRecords(agent.did);
    }
    const byAction = Object.fromEntries(
      records.map((record) => [record.action, record.principal?.id ?? "agent"]),
    );
    expect(byAction).toEqual({
      // Each reported by a service that proved itself with its certificate.
      "status.allocate": serviceUri("identity"),
      "agents.register": expect.stringMatching(/^[0-9a-f]{16}$/),
      "policies.grant": expect.stringMatching(/^[0-9a-f]{16}$/),
      query: "agent",
      "agents.revoke": expect.stringMatching(/^[0-9a-f]{16}$/),
    });
  });

  it("ignores a forged identity header sent straight to a service's plain port", async () => {
    const forged = await fetch(`${url(PORT.audit)}/records`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-client-cert": `URI=${serviceUri("vault")}`,
      },
      body: JSON.stringify({
        agentDid: "did:web:forged:agents:1",
        action: "forged",
        dataCategories: [],
        policy: { rule: "forged", decision: "allow" },
      }),
    });
    expect(forged.status).toBe(401);
  });

  it("drops a genuine service that bypasses Envoy to reach a TLS listener directly", async () => {
    await expect(
      asService("vault")(`https://localhost:${PORT.auditTls}/records`, {
        method: "POST",
        headers: { "x-forwarded-client-cert": `URI=${serviceUri("vault")}` },
      }),
    ).rejects.toThrow();
  });

  it("refuses at Envoy a service that may not call that service", async () => {
    // Only identity may reach revocation.
    await expect(
      asService("vault")(`${envoyUrl(PORT.envoyRevocation)}/agents`, { method: "POST" }),
    ).rejects.toThrow();
  });
});

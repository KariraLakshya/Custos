// Phase 6 DONE criterion (ADR 0014): two independent organisations. A's agent
// is verified by B from its credential and A's published status list alone.
// Then A's services are stopped and A's database made unreachable on the shared
// Postgres server (this is one machine, not two), and B still verifies. A's
// operator revokes through the publisher, and B refuses within one poll. Then
// the publisher's host goes away and, once the window passes, B refuses all of
// A's agents; when a fresh list is published again, B recovers, and the revoked
// agent stays refused.
//
// B never contacts A: B is configured with no URL of A's, and every request B
// makes is recorded and checked to be to the static host.
import { writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { connect, createServer as createTcpServer, type AddressInfo } from "node:net";
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import { buildServer as buildAuditServer, createDb as createAuditDb } from "@custos/audit";
import { createHttpAuditReporter } from "@custos/audit-client";
import {
  buildForeignCallProof,
  createLocalKeyProvider,
  multibaseToPublicKey,
  statusListCredentialUrl,
  verifyAuditRecord,
  type AuditRecord,
} from "@custos/core";
import {
  createForeignAgentGate,
  createInMemoryReplayGuard,
  createStatusCache,
  parseTrustAnchors,
  type ForeignAgentGate,
  type StatusCache,
} from "@custos/federation";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import {
  buildServer as buildRevocationServer,
  createDb as createRevocationDb,
} from "@custos/revocation";
import { createCustos, type Agent } from "@custos/sdk";
import { createTestControlPlane } from "@custos/testing/control-plane";
import { createMigratedTestDatabase, dropTestDatabase } from "@custos/vitest-config/hermetic-db";
import pg from "pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { publishOnce } from "./publisher/publish.js";
import { revokeFromPublisher } from "./publisher/revoke.js";
import { INIT, keyFor, makeKit, SEED, type Kit } from "./publisher/testkit.js";

// B's database is this run's hermetic one; A gets its own beside it.
const bDatabaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";

const POLL_INTERVAL_MS = 300;
// How long a list may be relied on, on both sides, through configuration only.
const WINDOW_SECONDS = 30;
// Allowance for the event loop and the request on top of one poll interval.
const POLL_SLACK_MS = 2_000;
const RECEIVER = "https://b.example/federation";
const A_LABEL = "org-a.test";
/** What B runs for each call; the agents sign this same request (ADR 0015). */
const B_REQUEST = { tool: "b-ledger", action: "read" } as const;

/**
 * One clock for B, the publisher and the agents' proofs. Moving it forward
 * stands in for waiting out the window; it is never moved back.
 */
const clock = {
  offsetMs: 0,
  now(): Date {
    return new Date(Date.now() + this.offsetMs);
  },
};

async function freePort(): Promise<number> {
  const server = createTcpServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function refusesConnections(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ port, host: "127.0.0.1" });
    socket.once("connect", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => resolve(true));
  });
}

/** The static host: serves the publisher's output file and nothing else. It is not A. */
async function startHost(port: number, file: string): Promise<Server> {
  const server = createServer((request, response) => {
    if (request.url !== "/status.json") return void response.writeHead(404).end();
    readFile(file, "utf8").then(
      (body) => response.writeHead(200, { "content-type": "application/json" }).end(body),
      () => response.writeHead(404).end(),
    );
  });
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  return server;
}

async function stopHost(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function didKey(url: string): Promise<{ did: string; publicKeyMultibase: string }> {
  const document = (await (await fetch(`${url}/.well-known/did.json`)).json()) as {
    id: string;
    verificationMethod: { publicKeyMultibase: string }[];
  };
  const method = document.verificationMethod[0];
  if (method === undefined) throw new Error(`${url} publishes no key`);
  return { did: document.id, publicKeyMultibase: method.publicKeyMultibase };
}

const cleanups: (() => Promise<unknown>)[] = [];
afterAll(async () => {
  for (const cleanup of cleanups.reverse()) {
    await cleanup().catch(() => undefined);
  }
});

describe("Phase 6: B verifies A's agent with A's services and database off", () => {
  it("allows, survives A going away, refuses after a published revocation, fails closed when stale, recovers", async () => {
    // ---- A: its own database, identity and revocation services ----
    const aDatabase = await createMigratedTestDatabase(bDatabaseUrl);
    cleanups.push(() => dropTestDatabase(bDatabaseUrl, aDatabase.name));
    const aIdentityDb = createIdentityDb(aDatabase.url);
    const aRevocationDb = createRevocationDb(aDatabase.url);
    const aControlPlane = createTestControlPlane(aIdentityDb);
    const operatorKey = await aControlPlane.key("operator", ["agents:register"]);
    const identityServiceKey = await aControlPlane.key("service", ["status:allocate"]);

    const [identityPort, revocationPort, hostPort, bAuditPort] = await Promise.all([
      freePort(),
      freePort(),
      freePort(),
      freePort(),
    ]);
    const aIdentityUrl = `http://127.0.0.1:${identityPort}`;
    const aRevocationUrl = `http://127.0.0.1:${revocationPort}`;
    const revocationDomain = `127.0.0.1:${revocationPort}`;

    // A's revocation service and the publisher share one identity (ADR 0014
    // open question 5): the same seed and domain.
    const aRevocation = await buildRevocationServer({
      db: aRevocationDb,
      signingKey: keyFor(SEED),
      controlPlaneAuth: aControlPlane.guard,
      didDomain: revocationDomain,
      auditReporter: { report: () => {} },
      broadcaster: { broadcast: async () => ({ delivered: 0, failed: [] }) },
    });
    await aRevocation.listen({ port: revocationPort, host: "127.0.0.1" });
    const aIdentity = await buildIdentityServer({
      db: aIdentityDb,
      controlPlaneAuth: aControlPlane.guard,
      serviceKey: identityServiceKey,
      didDomain: `127.0.0.1:${identityPort}`,
      issuerKey: {
        keyProvider: createLocalKeyProvider({
          importedKeys: { issuer: new Uint8Array(32).fill(41) },
        }),
        keyId: "issuer",
      },
      revocationUrl: aRevocationUrl,
      auditReporter: { report: () => {} },
    });
    await aIdentity.listen({ port: identityPort, host: "127.0.0.1" });
    let aRunning = true;
    cleanups.push(async () => {
      if (!aRunning) return;
      await aIdentity.close();
      await aRevocation.close();
      await aIdentityDb.$client.end();
      await aRevocationDb.$client.end();
    });

    // A registers two agents. One will be revoked; the other shows the stale
    // window applies to everyone, and that recovery lets it back in.
    const custos = createCustos({
      identityUrl: aIdentityUrl,
      revocationUrl: aRevocationUrl,
      // Registration never reaches a vault; A runs none here.
      vaultUrl: "http://127.0.0.1:9",
      operatorKey,
    });
    const revoked: Agent = await custos.register();
    const kept: Agent = await custos.register();
    expect(revoked.did.startsWith("did:web:127.0.0.1%3A")).toBe(true);

    // B is told A's keys out of band, while A is up (ADR 0014 decision 1).
    const aIdentityKey = await didKey(aIdentityUrl);
    const aStatusKey = await didKey(aRevocationUrl);

    // ---- The publisher, on A's operator's machine, and the static host ----
    const kit: Kit = await makeKit(
      { domain: revocationDomain, validitySeconds: WINDOW_SECONDS, stampSeconds: 10 },
      { clock },
    );
    cleanups.push(() => kit.cleanup());
    expect((await publishOnce(kit.config, kit.deps, INIT)).ok).toBe(true);
    let host = await startHost(hostPort, kit.out);
    let hostRunning = true;
    cleanups.push(async () => {
      if (hostRunning) await stopHost(host);
    });
    const statusFetchUrl = `http://127.0.0.1:${hostPort}/status.json`;

    // ---- B: its own database and audit service, the gate and the cache ----
    const bAuditDb = createAuditDb(bDatabaseUrl);
    const bControlPlane = createTestControlPlane(bAuditDb);
    const bAuditServiceKey = await bControlPlane.key("service", ["audit:write"]);
    const bAudit = await buildAuditServer({
      db: bAuditDb,
      controlPlaneAuth: bControlPlane.guard,
      didDomain: `127.0.0.1:${bAuditPort}`,
    });
    await bAudit.listen({ port: bAuditPort, host: "127.0.0.1" });
    const bAuditUrl = `http://127.0.0.1:${bAuditPort}`;
    cleanups.push(async () => {
      await bAudit.close();
      await bAuditDb.$client.end();
    });

    const anchors = parseTrustAnchors([
      {
        domain: A_LABEL,
        credentialIssuerDid: aIdentityKey.did,
        credentialIssuerPublicKey: aIdentityKey.publicKeyMultibase,
        statusIssuerDid: aStatusKey.did,
        statusIssuerPublicKey: aStatusKey.publicKeyMultibase,
        statusListId: statusListCredentialUrl(revocationDomain),
        statusFetchUrl,
        maxStatusAgeSeconds: WINDOW_SECONDS,
        enabled: true,
      },
    ]);
    if (!anchors.ok) throw new Error(anchors.error.issues.join("; "));

    const bFetches: string[] = [];
    const cache: StatusCache = createStatusCache({
      anchors: anchors.value,
      pollIntervalMs: POLL_INTERVAL_MS,
      maxClockSkewSeconds: 5,
      now: () => clock.now(),
      fetchImpl: ((input: string | URL | Request, init?: RequestInit) => {
        bFetches.push(String(input));
        return fetch(input, init);
      }) as typeof fetch,
    });
    cleanups.push(() => cache.stop());
    const auditErrors: unknown[] = [];
    const gate: ForeignAgentGate = createForeignAgentGate({
      anchors: anchors.value,
      statusViewFor: (anchor) => cache.viewFor(anchor),
      audience: RECEIVER,
      replay: createInMemoryReplayGuard(),
      now: () => clock.now(),
      maxProofSkewSeconds: 30,
      maxClockSkewSeconds: 5,
      audit: createHttpAuditReporter({
        auditUrl: bAuditUrl,
        serviceKey: bAuditServiceKey,
        onError: (error) => auditErrors.push(error),
      }),
    });

    /**
     * One call from an agent to B: a fresh proof each time, as a real agent
     * would, made for the request B runs (ADR 0015) unless `signedFor` says
     * otherwise, to stand in for a proof captured and spent elsewhere.
     */
    async function callB(agent: Agent, signedFor: { tool: string; action: string } = B_REQUEST) {
      const proof = await buildForeignCallProof({
        audience: RECEIVER,
        secretKey: Buffer.from(agent.secretKey, "hex"),
        now: clock.now(),
        request: signedFor,
      });
      const result = await gate.check({ credential: agent.credential, proof, ...B_REQUEST });
      return result.ok ? "allowed" : `${result.error.status} ${result.error.code}`;
    }

    await cache.start();

    // 1. A is up. B verifies both agents.
    expect(await callB(revoked)).toBe("allowed");
    expect(await callB(kept)).toBe("allowed");

    // 2. All of A goes away: its services stop and its database refuses connections.
    await aIdentity.close();
    await aRevocation.close();
    await aIdentityDb.$client.end();
    await aRevocationDb.$client.end();
    aRunning = false;
    const admin = new pg.Client({ connectionString: bDatabaseUrl });
    await admin.connect();
    try {
      await admin.query(`ALTER DATABASE "${aDatabase.name}" WITH ALLOW_CONNECTIONS false`);
      await admin.query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
        [aDatabase.name],
      );
    } finally {
      await admin.end();
    }
    expect(await refusesConnections(identityPort)).toBe(true);
    expect(await refusesConnections(revocationPort)).toBe(true);
    const probe = new pg.Client({ connectionString: aDatabase.url });
    await expect(probe.connect()).rejects.toThrow();
    await probe.end().catch(() => undefined);

    // A proof made for another action is refused, and is not written to
    // B's evidence log (it is an authentication failure, ADR 0008).
    expect(await callB(kept, { tool: B_REQUEST.tool, action: "write" })).toBe("401 UNAUTHORIZED");

    // 3. B still verifies A's agents from the credential and the list alone.
    expect(await callB(revoked)).toBe("allowed");
    expect(await callB(kept)).toBe("allowed");

    // 4. A's operator revokes one agent through the publisher (A is still off).
    const credentialPath = join(kit.dir, "revoked-agent.json");
    await writeFile(credentialPath, JSON.stringify(revoked.credential));
    const revocation = await revokeFromPublisher(kit.config, kit.deps, {
      target: { credentialPath },
      operator: "a-security-on-call",
      reason: "credential leaked",
      pinnedIdentity: aIdentityKey,
    });
    expect(revocation.ok).toBe(true);
    const revokedAt = Date.now();

    // B refuses it within one poll interval, with nothing but its own loop.
    await vi.waitFor(async () => expect(await callB(revoked)).toBe("403 AGENT_REVOKED"), {
      timeout: POLL_INTERVAL_MS + POLL_SLACK_MS,
      interval: 25,
    });
    const refusedAfterMs = Date.now() - revokedAt;
    expect(refusedAfterMs).toBeLessThanOrEqual(POLL_INTERVAL_MS + POLL_SLACK_MS);
    expect(await callB(kept)).toBe("allowed");

    // 5. The host goes away, and the window passes: B refuses everyone from A.
    await stopHost(host);
    hostRunning = false;
    clock.offsetMs += (WINDOW_SECONDS + 5) * 1000;
    await vi.waitFor(async () => expect(await callB(kept)).toBe("503 UNAVAILABLE"), {
      timeout: POLL_INTERVAL_MS + POLL_SLACK_MS,
      interval: 25,
    });
    // A revocation is never forgotten: still revoked, not merely unavailable.
    expect(await callB(revoked)).toBe("403 AGENT_REVOKED");

    // 6. The host is back and a fresh list is published: B recovers.
    host = await startHost(hostPort, kit.out);
    hostRunning = true;
    expect((await publishOnce(kit.config, kit.deps)).ok).toBe(true);
    await vi.waitFor(async () => expect(await callB(kept)).toBe("allowed"), {
      timeout: POLL_INTERVAL_MS + POLL_SLACK_MS,
      interval: 25,
    });
    expect(await callB(revoked)).toBe("403 AGENT_REVOKED");

    // B only ever fetched from the static host: never from A.
    expect(bFetches.length).toBeGreaterThan(2);
    expect(new Set(bFetches)).toEqual(new Set([statusFetchUrl]));

    // B's audit service holds signed records of what B decided about A's agents.
    const bAuditKey = multibaseToPublicKey((await didKey(bAuditUrl)).publicKeyMultibase);
    if (!bAuditKey.ok) throw new Error("B's audit key is unusable");
    let records: AuditRecord[] = [];
    await vi.waitFor(
      async () => {
        const body = (await (await fetch(`${bAuditUrl}/records`)).json()) as {
          records: string[];
        };
        records = body.records.map((record) => {
          const verified = verifyAuditRecord({ record, publicKey: bAuditKey.value });
          if (!verified.ok) throw new Error(`audit record failed verification`);
          return verified.value;
        });
        expect(
          records.some(
            (r) => r.agentDid === kept.did && r.reason?.includes("code=STATUS_STALE") === true,
          ),
        ).toBe(true);
        expect(
          records.filter((r) => r.agentDid === kept.did && r.policy.decision === "allow").length,
        ).toBeGreaterThanOrEqual(4);
      },
      { timeout: 5_000, interval: 100 },
    );
    expect(auditErrors).toEqual([]);
    for (const record of records) {
      expect(record.policy.rule).toBe(`foreign:${A_LABEL}`);
      expect(record.tool).toBe("b-ledger");
      // The proof made for "write" was refused before any audit record.
      expect(record.action).toBe("read");
    }
    const revokedRecords = records.filter((r) => r.agentDid === revoked.did);
    expect(revokedRecords[0]?.policy.decision).toBe("allow");
    expect(revokedRecords.at(-1)).toMatchObject({
      policy: { decision: "deny" },
      reason: `issuer=${aIdentityKey.did} code=AGENT_REVOKED`,
    });
  }, 120_000);
});

// The demo's story against real A services and B's real audit service, in
// process; the presenter's Enter presses are replaced by waiting for what
// each step should show.
import { mkdtemp, rm } from "node:fs/promises";
import { createServer as createTcpServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer as buildAuditServer, createDb as createAuditDb } from "@custos/audit";
import { createLocalKeyProvider, multibaseToPublicKey, verifyAuditRecord } from "@custos/core";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import {
  buildServer as buildRevocationServer,
  createDb as createRevocationDb,
} from "@custos/revocation";
import { createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, describe, expect, it, vi } from "vitest";
import { ORGANISATION_A, runFederationStory, type Outcome, type StoryAgent } from "./story.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const SEED = "5a".repeat(32);

async function freePort(): Promise<number> {
  const server = createTcpServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

const cleanups: (() => Promise<unknown>)[] = [];
afterAll(async () => {
  for (const cleanup of cleanups.reverse()) await cleanup().catch(() => undefined);
});

interface Stack {
  readonly identityPort: number;
  readonly revocationPort: number;
  readonly auditPort: number;
  readonly hostPort: number;
  readonly revocationDomain: string;
  readonly operatorKey: string;
  readonly bAuditKey: string;
  readonly workDir: string;
  readonly stopA: () => Promise<void>;
  readonly aIsRunning: () => boolean;
}

/** A's real identity and revocation services and B's real audit service, in process. */
async function startStack(): Promise<Stack> {
  const identityDb = createIdentityDb(databaseUrl);
  const revocationDb = createRevocationDb(databaseUrl);
  const auditDb = createAuditDb(databaseUrl);
  cleanups.push(() => identityDb.$client.end());
  cleanups.push(() => revocationDb.$client.end());
  cleanups.push(() => auditDb.$client.end());
  const controlPlane = createTestControlPlane(identityDb);
  const operatorKey = await controlPlane.key("operator", ["agents:register"]);
  const identityServiceKey = await controlPlane.key("service", ["status:allocate"]);
  const bAuditKey = await controlPlane.key("service", ["audit:write"]);

  const [identityPort, revocationPort, auditPort, hostPort] = await Promise.all([
    freePort(),
    freePort(),
    freePort(),
    freePort(),
  ]);
  const revocationDomain = `127.0.0.1:${revocationPort}`;
  const revocation = await buildRevocationServer({
    db: revocationDb,
    signingKey: {
      keyProvider: createLocalKeyProvider({
        importedKeys: { revocation: Buffer.from(SEED, "hex") },
      }),
      keyId: "revocation",
    },
    controlPlaneAuth: controlPlane.guard,
    didDomain: revocationDomain,
    auditReporter: { report: () => {} },
    broadcaster: { broadcast: async () => ({ delivered: 0, failed: [] }) },
  });
  await revocation.listen({ port: revocationPort, host: "127.0.0.1" });
  const identity = await buildIdentityServer({
    db: identityDb,
    controlPlaneAuth: controlPlane.guard,
    serviceKey: identityServiceKey,
    didDomain: `127.0.0.1:${identityPort}`,
    issuerKey: {
      keyProvider: createLocalKeyProvider({
        importedKeys: { issuer: new Uint8Array(32).fill(52) },
      }),
      keyId: "issuer",
    },
    revocationUrl: `http://127.0.0.1:${revocationPort}`,
    auditReporter: { report: () => {} },
  });
  await identity.listen({ port: identityPort, host: "127.0.0.1" });
  let aRunning = true;
  const stopA = async (): Promise<void> => {
    aRunning = false;
    await identity.close();
    await revocation.close();
  };
  cleanups.push(async () => {
    if (aRunning) await stopA();
  });
  const audit = await buildAuditServer({
    db: auditDb,
    controlPlaneAuth: controlPlane.guard,
    didDomain: `127.0.0.1:${auditPort}`,
  });
  await audit.listen({ port: auditPort, host: "127.0.0.1" });
  cleanups.push(() => audit.close());
  const workDir = await mkdtemp(join(tmpdir(), "custos-federation-demo-"));
  cleanups.push(() => rm(workDir, { recursive: true, force: true }));

  return {
    identityPort,
    revocationPort,
    auditPort,
    hostPort,
    revocationDomain,
    operatorKey,
    bAuditKey,
    workDir,
    stopA,
    aIsRunning: () => aRunning,
  };
}

describe("runFederationStory", () => {
  it("allows both agents, keeps allowing with A off, refuses agent 1 once fired, and leaves agent 2 working", async () => {
    const {
      identityPort,
      revocationPort,
      auditPort,
      hostPort,
      revocationDomain,
      operatorKey,
      bAuditKey,
      workDir,
      stopA,
      aIsRunning,
    } = await startStack();
    const aRunning = (): boolean => aIsRunning();
    const decisions: { agent: string; outcome: Outcome; aOff: boolean }[] = [];
    const lines: string[] = [];
    const seen = (agent: string, outcome: Outcome, aOff: boolean) =>
      decisions.some((d) => d.agent === agent && d.outcome === outcome && d.aOff === aOff);
    const prompts: string[] = [];
    const stop = new AbortController();

    const result = await runFederationStory({
      identityUrl: `http://127.0.0.1:${identityPort}`,
      revocationUrl: `http://127.0.0.1:${revocationPort}`,
      revocationDomain,
      revocationSigningSeedHex: SEED,
      operatorKey,
      bAuditUrl: `http://127.0.0.1:${auditPort}`,
      bAuditServiceKey: bAuditKey,
      hostPort,
      workDir,
      trafficIntervalMs: 50,
      pollIntervalMs: 200,
      out: (line) => lines.push(line),
      stopA,
      signal: stop.signal,
      onDecision: (agent: StoryAgent, outcome) =>
        decisions.push({ agent: agent.label, outcome, aOff: !aRunning() }),
      waitForStep: async (prompt) => {
        prompts.push(prompt);
        if (prompts.length === 1) {
          // A is up: both agents allowed.
          await vi.waitFor(() => {
            expect(seen("agent 1", "allowed", false)).toBe(true);
            expect(seen("agent 2", "allowed", false)).toBe(true);
          });
        } else if (prompts.length === 2) {
          // A is off: both still allowed.
          await vi.waitFor(() => {
            expect(seen("agent 1", "allowed", true)).toBe(true);
            expect(seen("agent 2", "allowed", true)).toBe(true);
          });
        } else {
          // Fired: agent 1 refused, and agent 2 still allowed after that.
          const firedAt = decisions.findIndex((d) => d.outcome === "403 AGENT_REVOKED");
          expect(firedAt).toBeGreaterThanOrEqual(0);
          await vi.waitFor(() => {
            expect(
              decisions
                .slice(firedAt)
                .some((d) => d.agent === "agent 2" && d.outcome === "allowed"),
            ).toBe(true);
          });
        }
      },
    });

    expect(prompts).toHaveLength(3);
    expect(result.refusedAfterMs).toBeTypeOf("number");
    expect(lines.join("\n")).toContain("refused it (403 AGENT_REVOKED)");
    expect(lines.join("\n")).toContain("on its own next poll");
    // Measured on B's own poll loop (200 ms here), not a forced refresh.
    expect(result.refusedAfterMs).toBeLessThanOrEqual(200 * 3 + 5_000);
    expect(lines.join("\n")).not.toContain(SEED);
    // Once fired, never allowed again.
    const firedAt = decisions.findIndex((d) => d.outcome === "403 AGENT_REVOKED");
    expect(
      decisions.slice(firedAt).filter((d) => d.agent === "agent 1" && d.outcome === "allowed"),
    ).toEqual([]);

    // The dashboard's source: B's audit service, with signed foreign: records.
    const document = (await (
      await fetch(`http://127.0.0.1:${auditPort}/.well-known/did.json`)
    ).json()) as { verificationMethod: { publicKeyMultibase: string }[] };
    const key = multibaseToPublicKey(document.verificationMethod[0]?.publicKeyMultibase ?? "");
    if (!key.ok) throw new Error("audit key");
    await vi.waitFor(async () => {
      const { records } = (await (await fetch(`http://127.0.0.1:${auditPort}/records`)).json()) as {
        records: string[];
      };
      const reasons = records
        .map((record) => verifyAuditRecord({ record, publicKey: key.value }))
        .flatMap((verified) => (verified.ok ? [verified.value] : []))
        .filter((claims) => claims.policy.rule === `foreign:${ORGANISATION_A}`)
        .map((claims) => `${claims.policy.decision} ${claims.reason ?? ""}`);
      expect(reasons.some((r) => r.startsWith("allow "))).toBe(true);
      expect(reasons.some((r) => r.startsWith("deny ") && r.endsWith("code=AGENT_REVOKED"))).toBe(
        true,
      );
    });
  }, 60_000);

  it("stops quietly at a prompt (Ctrl-C), leaves A running, and frees what it started", async () => {
    const stack = await startStack();
    const stop = new AbortController();
    let stopACalled = false;
    const result = await runFederationStory({
      identityUrl: `http://127.0.0.1:${stack.identityPort}`,
      revocationUrl: `http://127.0.0.1:${stack.revocationPort}`,
      revocationDomain: stack.revocationDomain,
      revocationSigningSeedHex: SEED,
      operatorKey: stack.operatorKey,
      bAuditUrl: `http://127.0.0.1:${stack.auditPort}`,
      bAuditServiceKey: stack.bAuditKey,
      hostPort: stack.hostPort,
      workDir: stack.workDir,
      trafficIntervalMs: 50,
      pollIntervalMs: 200,
      out: () => {},
      stopA: async () => {
        stopACalled = true;
      },
      signal: stop.signal,
      // The presenter presses Ctrl-C at the first prompt.
      waitForStep: () => {
        stop.abort();
        return new Promise(() => undefined);
      },
    });
    expect(result.refusedAfterMs).toBeUndefined();
    expect(stopACalled).toBe(false);
    // The static host it started is closed again.
    const host = createTcpServer();
    await new Promise<void>((resolve, reject) => {
      host.once("error", reject);
      host.listen(stack.hostPort, "127.0.0.1", () => resolve());
    });
    await new Promise<void>((resolve) => host.close(() => resolve()));
  });

  it("fails loudly when A's identity service cannot be reached", async () => {
    const closed = await freePort();
    await expect(
      runFederationStory({
        identityUrl: `http://127.0.0.1:${closed}`,
        revocationUrl: `http://127.0.0.1:${closed}`,
        revocationDomain: `127.0.0.1:${closed}`,
        revocationSigningSeedHex: SEED,
        operatorKey: "unused",
        bAuditUrl: "http://127.0.0.1:9",
        bAuditServiceKey: "unused",
        hostPort: await freePort(),
        workDir: tmpdir(),
        trafficIntervalMs: 50,
        pollIntervalMs: 200,
        out: () => {},
        stopA: async () => {},
        signal: new AbortController().signal,
        waitForStep: async () => {},
      }),
    ).rejects.toThrow();
  });
});

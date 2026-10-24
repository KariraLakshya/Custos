import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { createHttpAuditReporter } from "@custos/audit-client";
import {
  buildForeignCallProof,
  buildRegistrationRequest,
  createLocalKeyProvider,
  didWebFromDomain,
  statusListCredentialUrl,
} from "@custos/core";
import {
  createForeignAgentGate,
  createInMemoryReplayGuard,
  createStatusCache,
  parseTrustAnchors,
} from "@custos/federation";
import { publishOnce, runPublisher, type PublisherConfig } from "../publisher/publish.js";
import { revokeFromPublisher } from "../publisher/revoke.js";

/** What the receiving organisation (B) is called on screen, and A's label in B's trust anchor. */
export const ORGANISATION_A = "org-a.example";
const RECEIVER = "https://org-b.example/federation";
/** What B runs for each call; the agents sign this same request (ADR 0015). */
const B_REQUEST = { tool: "b-ledger", action: "read" } as const;
// The production values ADR 0014 recommends: a one-hour window, re-signed every 20 minutes.
const WINDOW_SECONDS = 3600;
const STAMP_SECONDS = 1200;
const MAX_CLOCK_SKEW_SECONDS = 5;

export interface StoryAgent {
  readonly label: string;
  readonly did: string;
  readonly credential: Record<string, unknown>;
  readonly secretKey: Uint8Array;
}

export type Outcome = "allowed" | `${number} ${string}`;

export interface StoryDeps {
  /** A's identity service, which registers the two agents. */
  readonly identityUrl: string;
  /** A's revocation service: its URL (to read its key once) and its DID domain (the list's identity). */
  readonly revocationUrl: string;
  readonly revocationDomain: string;
  /**
   * A's revocation signing seed, held in memory only. The publisher signs as
   * A's revocation identity (ADR 0014 open question 5); never printed.
   */
  readonly revocationSigningSeedHex: string;
  /** A's operator key, with `agents:register`. */
  readonly operatorKey: string;
  /** B's audit service and B's own key for it (`audit:write`). */
  readonly bAuditUrl: string;
  readonly bAuditServiceKey: string;
  /** The static host for A's published list: not A, a plain file server. */
  readonly hostPort: number;
  /** A fresh directory for the publisher's journal, state and output. */
  readonly workDir: string;
  readonly trafficIntervalMs: number;
  readonly pollIntervalMs: number;
  readonly out: (line: string) => void;
  /** Resolves when the presenter is ready for the next step. */
  readonly waitForStep: (prompt: string) => Promise<void>;
  /** Stops all of A's services. */
  readonly stopA: () => Promise<void>;
  /** Aborted to end the story at any point (Ctrl-C). */
  readonly signal: AbortSignal;
  /** Every decision B makes, for the terminal and for tests. */
  readonly onDecision?: (agent: StoryAgent, outcome: Outcome) => void;
  readonly fetchImpl?: typeof fetch;
}

export interface StoryResult {
  /** Milliseconds from the publisher finishing the revocation to B refusing the agent. */
  readonly refusedAfterMs: number | undefined;
}

class Aborted extends Error {}

async function registerAgent(deps: StoryDeps, label: string): Promise<StoryAgent> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const request = await buildRegistrationRequest({
    audience: didWebFromDomain(new URL(deps.identityUrl).host),
    now: new Date(),
  });
  const response = await fetchImpl(new URL("/agents", deps.identityUrl), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${deps.operatorKey}` },
    body: JSON.stringify(request.body),
  });
  if (!response.ok) throw new Error(`registering ${label} failed: HTTP ${response.status}`);
  const body = (await response.json()) as { did?: unknown; credential?: unknown };
  if (
    typeof body.did !== "string" ||
    typeof body.credential !== "object" ||
    body.credential === null
  ) {
    throw new Error(`registering ${label}: unexpected answer from A's identity service`);
  }
  return {
    label,
    did: body.did,
    credential: body.credential as Record<string, unknown>,
    secretKey: request.secretKey,
  };
}

async function publishedKey(
  deps: StoryDeps,
  url: string,
): Promise<{ did: string; publicKeyMultibase: string }> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const document = (await (await fetchImpl(`${url}/.well-known/did.json`)).json()) as {
    id?: unknown;
    verificationMethod?: { publicKeyMultibase?: unknown }[];
  };
  const key = document.verificationMethod?.[0]?.publicKeyMultibase;
  if (typeof document.id !== "string" || typeof key !== "string") {
    throw new Error(`${url} did not publish a usable DID document`);
  }
  return { did: document.id, publicKeyMultibase: key };
}

async function startHost(port: number, file: string): Promise<Server> {
  const server = createServer((request, response) => {
    if (request.url !== "/status.json") return void response.writeHead(404).end();
    readFile(file, "utf8").then(
      (body) => response.writeHead(200, { "content-type": "application/json" }).end(body),
      () => response.writeHead(404).end(),
    );
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve());
  });
  return server;
}

function shortDid(did: string): string {
  const last = did.split(":").at(-1) ?? did;
  return last.length > 14 ? `${last.slice(0, 6)}…${last.slice(-4)}` : last;
}

/**
 * The two-organisation story behind `custos-admin demo-federation`, step by
 * step at the presenter's pace: A's agents call B and are allowed; A is
 * switched off and they are still allowed; A's security operator fires one
 * through the publisher and B refuses it on its next poll, while the other
 * carries on. B's decisions go to B's audit service, which the dashboard
 * shows. Everything it starts, it stops; the seed is never printed.
 */
export async function runFederationStory(deps: StoryDeps): Promise<StoryResult> {
  const { out, signal } = deps;
  const cleanups: (() => Promise<unknown>)[] = [];
  const stopPublisher = new AbortController();
  let refusedAfterMs: number | undefined;

  async function step(prompt: string): Promise<void> {
    if (signal.aborted) throw new Aborted();
    // Listen before asking: a stop that arrives while the prompt is being
    // shown (or from inside it) must not be missed.
    const aborted = new Promise<void>((_, reject) => {
      const fail = (): void => reject(new Aborted());
      if (signal.aborted) fail();
      else signal.addEventListener("abort", fail, { once: true });
    });
    aborted.catch(() => undefined);
    await Promise.race([deps.waitForStep(prompt), aborted]);
    if (signal.aborted) throw new Aborted();
  }

  try {
    // ---- A registers two agents, and B is told A's keys out of band ----
    const agents = [await registerAgent(deps, "agent 1"), await registerAgent(deps, "agent 2")];
    const [first] = agents;
    if (first === undefined) throw new Error("unreachable");
    const identityKey = await publishedKey(deps, deps.identityUrl);
    const statusKey = await publishedKey(deps, deps.revocationUrl);

    // ---- A's publisher (on its security operator's machine) and the static host ----
    const site = join(deps.workDir, "site");
    await mkdir(site, { recursive: true });
    const config: PublisherConfig = {
      domain: deps.revocationDomain,
      dir: join(deps.workDir, "publisher"),
      out: join(site, "status.json"),
      validitySeconds: WINDOW_SECONDS,
      stampSeconds: STAMP_SECONDS,
      maxClockSkewSeconds: MAX_CLOCK_SKEW_SECONDS,
    };
    const publisherDeps = {
      keyProvider: createLocalKeyProvider({
        importedKeys: { publisher: Buffer.from(deps.revocationSigningSeedHex, "hex") },
      }),
      keyId: "publisher",
      clock: { now: () => new Date() },
    };
    const initialised = await publishOnce(config, publisherDeps, {
      init: true,
      acknowledgeNoPublishedList: true,
    });
    if (!initialised.ok) throw new Error(`publisher init failed: ${initialised.error.code}`);
    const publisherLoop = runPublisher(config, publisherDeps, {
      signal: stopPublisher.signal,
      onCycle: (result) => {
        if (!result.ok) out(`publisher: re-sign failed (${result.error.code})`);
      },
    });
    cleanups.push(async () => {
      stopPublisher.abort();
      await publisherLoop;
    });
    const host = await startHost(deps.hostPort, config.out);
    cleanups.push(async () => {
      host.closeAllConnections();
      await new Promise<void>((resolve) => host.close(() => resolve()));
    });

    // ---- B: its trust anchor for A, its status cache and its gate ----
    const anchors = parseTrustAnchors([
      {
        domain: ORGANISATION_A,
        credentialIssuerDid: identityKey.did,
        credentialIssuerPublicKey: identityKey.publicKeyMultibase,
        statusIssuerDid: statusKey.did,
        statusIssuerPublicKey: statusKey.publicKeyMultibase,
        statusListId: statusListCredentialUrl(deps.revocationDomain),
        statusFetchUrl: `http://127.0.0.1:${deps.hostPort}/status.json`,
        maxStatusAgeSeconds: WINDOW_SECONDS,
        enabled: true,
      },
    ]);
    if (!anchors.ok) throw new Error(`B's trust anchor: ${anchors.error.issues.join("; ")}`);
    const [anchor] = anchors.value;
    if (anchor === undefined) throw new Error("unreachable");
    const cache = createStatusCache({
      anchors: anchors.value,
      pollIntervalMs: deps.pollIntervalMs,
      maxClockSkewSeconds: MAX_CLOCK_SKEW_SECONDS,
      now: () => new Date(),
      ...(deps.fetchImpl === undefined ? {} : { fetchImpl: deps.fetchImpl }),
      onEvent: (event) => {
        if (event.kind === "failed") out(`B: could not refresh A's list (${event.reason})`);
      },
    });
    cleanups.push(() => cache.stop());
    const gate = createForeignAgentGate({
      anchors: anchors.value,
      statusViewFor: (a) => cache.viewFor(a),
      audience: RECEIVER,
      replay: createInMemoryReplayGuard(),
      now: () => new Date(),
      maxProofSkewSeconds: 30,
      maxClockSkewSeconds: MAX_CLOCK_SKEW_SECONDS,
      audit: createHttpAuditReporter({
        auditUrl: deps.bAuditUrl,
        serviceKey: deps.bAuditServiceKey,
        ...(deps.fetchImpl === undefined ? {} : { fetchImpl: deps.fetchImpl }),
        onError: () => out("B: an audit record could not be written"),
      }),
    });
    await cache.start();

    async function callB(agent: StoryAgent): Promise<Outcome> {
      const proof = await buildForeignCallProof({
        audience: RECEIVER,
        secretKey: agent.secretKey,
        now: new Date(),
        request: B_REQUEST,
      });
      const result = await gate.check({ credential: agent.credential, proof, ...B_REQUEST });
      const outcome: Outcome = result.ok
        ? "allowed"
        : `${result.error.status} ${result.error.code}`;
      deps.onDecision?.(agent, outcome);
      return outcome;
    }

    // ---- A's agents call B on a steady beat ----
    let traffic: ReturnType<typeof setTimeout> | undefined;
    let trafficStopped = false;
    const lastOutcome = new Map<string, Outcome>();
    const beat = async (): Promise<void> => {
      for (const agent of agents) {
        if (trafficStopped) return;
        const outcome = await callB(agent);
        // Only changes, so the terminal stays readable at the prompt; every
        // decision is on the dashboard.
        if (lastOutcome.get(agent.label) !== outcome) {
          lastOutcome.set(agent.label, outcome);
          out(`  ${agent.label} (${shortDid(agent.did)}) → B: ${outcome}`);
        }
      }
      if (!trafficStopped) traffic = setTimeout(() => void beat(), deps.trafficIntervalMs);
    };
    void beat();
    cleanups.push(async () => {
      trafficStopped = true;
      clearTimeout(traffic);
    });

    out("");
    out(`Company A (${ORGANISATION_A}) registered two agents; company B trusts A's keys.`);
    out("Both agents are calling B every few seconds. Watch the dashboard's");
    out('"Across organisations" panel.');
    await step("Press Enter to switch company A off (its identity and revocation services stop).");

    await deps.stopA();
    out("");
    out("Company A is off. B keeps checking A's agents from their signed credentials and A's");
    out("published list on the static host, without contacting A.");
    await step("Press Enter to fire agent 1 through A's publisher (A stays off).");

    const credentialPath = join(deps.workDir, "agent-1.json");
    await writeFile(credentialPath, JSON.stringify(first.credential));
    const revoked = await revokeFromPublisher(config, publisherDeps, {
      target: { credentialPath },
      operator: "a-security-on-call",
      reason: "demo: credential leaked",
      pinnedIdentity: identityKey,
    });
    if (!revoked.ok) throw new Error(`the publisher could not revoke: ${revoked.error.code}`);
    const publishedAt = Date.now();
    // B learns on its own next poll (no forced refresh). Wait until B's own
    // loop has taken in a list signed after the revocation, then let agent 1
    // call once: the time printed is B's real reaction, and the dashboard gets
    // one refusal, not a burst of calls.
    let outcome: Outcome = "allowed";
    const giveUpAt = publishedAt + deps.pollIntervalMs * 3 + 5_000;
    while (!signal.aborted && Date.now() < giveUpAt) {
      const view = cache.viewFor(anchor);
      if (
        view !== undefined &&
        view.validFrom.getTime() >= revoked.value.published.validFrom.getTime()
      ) {
        outcome = await callB(first);
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    if (signal.aborted) throw new Aborted();
    refusedAfterMs = outcome === "allowed" ? undefined : Date.now() - publishedAt;
    out("");
    out(
      refusedAfterMs === undefined
        ? "Agent 1 fired, but B has not refused it yet: check B's status cache in the log above."
        : `Agent 1 fired. B refused it (${outcome}) ${refusedAfterMs} ms after the publisher published, on its own next poll.`,
    );
    out("Agent 2 keeps working.");
    await step("Press Enter (or Ctrl-C) to stop the demo.");
  } catch (error) {
    if (!(error instanceof Aborted)) throw error;
  } finally {
    for (const cleanup of cleanups.reverse()) await cleanup().catch(() => undefined);
  }
  return { refusedAfterMs };
}

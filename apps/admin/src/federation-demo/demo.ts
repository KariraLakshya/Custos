import { DEMO_KEY_LIFETIME_MS, buildServiceEnv, waitUntilReady } from "../demo.js";
import type { DemoChild, DemoDeps, DemoHandle, ServiceSpec } from "../demo.js";
import type { StoryDeps, StoryResult } from "./story.js";

/** Where A's services send audit events: nowhere. A's records must not land in B's log. */
const A_AUDIT_URL = "http://127.0.0.1:9";
export const HOST_PORT = 4006;
const STOP_WAIT_MS = 5_000;

interface Role extends ServiceSpec {
  /** Which organisation runs it, for the banner and the deliberate stop. */
  readonly organisation: "A" | "B";
}

// A: identity and revocation. B: its audit service and the dashboard reading it.
// No vault: B's gate is in this process, and A's tools are not part of the story.
const ROLES: readonly Role[] = [
  { name: "audit", dir: "services/audit", port: 4004, readyPath: "/health", organisation: "B" },
  {
    name: "revocation",
    dir: "services/revocation",
    port: 4003,
    readyPath: "/health",
    organisation: "A",
  },
  {
    name: "identity",
    dir: "services/identity",
    port: 4001,
    readyPath: "/health",
    organisation: "A",
  },
  { name: "dashboard", dir: "apps/dashboard", port: 4005, readyPath: "/", organisation: "B" },
];

export interface FederationDemoDeps extends Pick<
  DemoDeps,
  | "store"
  | "clock"
  | "out"
  | "spawn"
  | "fetch"
  | "sleep"
  | "isPortFree"
  | "randomHex"
  | "baseEnv"
  | "databaseUrl"
  | "repoRoot"
> {
  /** The presenter's Enter key. */
  readonly waitForStep: (prompt: string) => Promise<void>;
  /** A fresh directory for the publisher; removed by `cleanupWorkDir`. */
  readonly makeWorkDir: () => Promise<string>;
  readonly cleanupWorkDir: (dir: string) => Promise<void>;
  /** The story itself; injected so the process handling can be tested on its own. */
  readonly runStory: (deps: StoryDeps) => Promise<StoryResult>;
}

/**
 * `custos-admin demo-federation`: two organisations on one machine. A runs its
 * identity and revocation services; B runs its audit service and the
 * dashboard; this process plays A's agents, A's publisher, the static host
 * and B's gate. Switching A off kills A's processes on purpose, which must
 * not end the demo; any other process dying does. Seeds and keys live in
 * memory only, and the keys are revoked on stop.
 */
export async function startFederationDemo(deps: FederationDemoDeps): Promise<DemoHandle> {
  const busy: number[] = [];
  for (const port of [...ROLES.map((role) => role.port), HOST_PORT]) {
    if (!(await deps.isPortFree(port))) busy.push(port);
  }
  if (busy.length > 0) {
    throw new Error(
      `port${busy.length > 1 ? "s" : ""} ${busy.sort((a, b) => a - b).join(", ")} already in use. ` +
        "Stop whatever is running there (pnpm demo uses the same ports); on Windows, a port " +
        "reserved by WinNAT fails the same way (see docs/state.md, Gotchas).",
    );
  }

  const now = deps.clock.now();
  const expiresAt = new Date(now.getTime() + DEMO_KEY_LIFETIME_MS);
  const keys: Record<string, string> = {};
  const keyIds: string[] = [];
  // A's keys and B's key share one api_keys table here (one dev database);
  // each is scoped to its own job.
  for (const key of [
    {
      variable: "IDENTITY_SERVICE_KEY",
      kind: "service",
      name: "a-identity",
      scopes: ["status:allocate", "audit:write"],
    },
    {
      variable: "REVOCATION_SERVICE_KEY",
      kind: "service",
      name: "a-revocation",
      scopes: ["audit:write"],
    },
    {
      variable: "A_OPERATOR_KEY",
      kind: "operator",
      name: "a-operator",
      scopes: ["agents:register"],
    },
    { variable: "B_AUDIT_KEY", kind: "service", name: "b-gate", scopes: ["audit:write"] },
  ] as const) {
    const created = await deps.store.create({
      kind: key.kind,
      name: `federation-demo-${key.name}`,
      scopes: key.scopes,
      expiresAt,
      now,
    });
    if (!created.ok) throw new Error(`demo key ${key.name} not created: ${created.error.code}`);
    keys[key.variable] = created.token;
    keyIds.push(created.id);
  }
  const seeds = {
    IDENTITY_ISSUER_SEED: deps.randomHex(32),
    REVOCATION_SIGNING_SEED: deps.randomHex(32),
  };

  const children = new Map<string, { child: DemoChild; exited: Promise<void> }>();
  const deliberatelyStopped = new Set<string>();
  const storyStop = new AbortController();
  let workDir: string | undefined;
  let story: Promise<unknown> | undefined = undefined;
  let stopped = false;
  let finish: (reason: string) => void = () => {};
  const finished = new Promise<string>((resolve) => {
    finish = resolve;
  });

  const kill = (): void => {
    for (const { child } of children.values()) child.kill();
  };
  const stop = async (reason = "stopped"): Promise<void> => {
    if (stopped) return;
    stopped = true;
    storyStop.abort();
    try {
      // Let the story close what it started (host, publisher, cache) first.
      if (story !== undefined) await Promise.race([story, deps.sleep(STOP_WAIT_MS)]);
    } catch {
      // The story's own failure is reported where it is awaited.
    }
    kill();
    try {
      const revokedAt = deps.clock.now();
      await Promise.all(keyIds.map((id) => deps.store.revoke(id, revokedAt)));
    } catch {
      deps.out("could not revoke the demo keys; they expire in 12 hours");
    }
    if (workDir !== undefined) await deps.cleanupWorkDir(workDir).catch(() => undefined);
    finish(reason);
  };

  /** Switching A off: A's processes are killed on purpose, so their exit is not a failure. */
  const stopA = async (): Promise<void> => {
    const waits: Promise<void>[] = [];
    for (const role of ROLES.filter((r) => r.organisation === "A")) {
      const running = children.get(role.name);
      if (running === undefined) continue;
      deliberatelyStopped.add(role.name);
      running.child.kill();
      waits.push(running.exited);
    }
    await Promise.race([Promise.all(waits), deps.sleep(STOP_WAIT_MS)]);
  };

  try {
    for (const role of ROLES) {
      let hasExited = false;
      const env = buildServiceEnv(role, {
        baseEnv: deps.baseEnv,
        databaseUrl: deps.databaseUrl,
        keys,
        seeds,
      });
      if (role.organisation === "A") env["AUDIT_URL"] = A_AUDIT_URL;
      const child = deps.spawn(`${deps.repoRoot}/${role.dir}/dist/index.js`, {
        cwd: `${deps.repoRoot}/${role.dir}`,
        env,
      });
      let markExited: () => void = () => {};
      const exited = new Promise<void>((resolve) => {
        markExited = resolve;
      });
      children.set(role.name, { child, exited });
      child.onExit((code) => {
        hasExited = true;
        markExited();
        if (stopped || deliberatelyStopped.has(role.name)) return;
        deps.out(`${role.name} stopped unexpectedly (exit ${code ?? "signal"}); shutting down`);
        void stop("a service stopped unexpectedly");
      });
      if (!(await waitUntilReady(deps, role, () => hasExited))) {
        throw new Error(`${role.name} did not start (port ${role.port}); see its output above`);
      }
    }
    workDir = await deps.makeWorkDir();
  } catch (error: unknown) {
    await stop();
    throw error;
  }

  printBanner(deps);
  story = deps
    .runStory({
      identityUrl: "http://localhost:4001",
      revocationUrl: "http://localhost:4003",
      revocationDomain: "localhost:4003",
      revocationSigningSeedHex: seeds.REVOCATION_SIGNING_SEED,
      operatorKey: keys["A_OPERATOR_KEY"]!,
      bAuditUrl: "http://localhost:4004",
      bAuditServiceKey: keys["B_AUDIT_KEY"]!,
      hostPort: HOST_PORT,
      workDir,
      trafficIntervalMs: 3_000,
      pollIntervalMs: 1_000,
      out: deps.out,
      waitForStep: deps.waitForStep,
      stopA,
      signal: storyStop.signal,
    })
    .then(
      () => void stop(),
      (error: unknown) => {
        deps.out(`demo failed: ${error instanceof Error ? error.message : String(error)}`);
        void stop("the story failed");
      },
    );

  return { finished, stop: () => stop(), kill };
}

function printBanner(deps: Pick<FederationDemoDeps, "out">): void {
  for (const line of [
    "",
    "Custos federation demo: two organisations on this machine.",
    "",
    '  dashboard   http://localhost:4005   open it now: watch the "Across organisations" panel',
    "  company A   identity http://localhost:4001, revocation http://localhost:4003",
    "  company B   audit http://localhost:4004 (the dashboard reads it); B's gate runs in this terminal",
    "  A's list    http://127.0.0.1:4006/status.json (a plain file host, not A)",
    "",
    "On one machine with one database: switching A off stops A's services; the database stays",
    "up because B's audit uses it too. (The e2e test, pnpm --filter @custos/admin test:e2e,",
    "proves the stronger case with A's database off as well.) The dashboard's single-company",
    "panels read A's revocation service, so they go quiet once A is off: B's decisions are in",
    "the cross-organisation panel. Keys expire in 12 hours and are revoked on stop.",
    "",
  ]) {
    deps.out(line);
  }
}

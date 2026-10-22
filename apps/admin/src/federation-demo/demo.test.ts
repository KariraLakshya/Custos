import { createApiKeyStore } from "@custos/control-plane-auth";
import { fixedClock } from "@custos/testing";
import { drizzle } from "drizzle-orm/node-postgres";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { runAdminCli } from "../admin.js";
import type { DemoChild, DemoHandle } from "../demo.js";
import { HOST_PORT, startFederationDemo, type FederationDemoDeps } from "./demo.js";
import type { StoryDeps, StoryResult } from "./story.js";

// Real Postgres for the keys, as demo.test.ts does: their creation and
// revocation are real rows. Processes and the story are fakes.
const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = drizzle(databaseUrl);
const store = createApiKeyStore(db);
const clock = fixedClock("2026-10-22T12:00:00.000Z");

afterAll(async () => {
  await db.$client.end();
});

class FakeChild implements DemoChild {
  killed = false;
  private callbacks: Array<(code: number | null) => void> = [];
  onExit(callback: (code: number | null) => void): void {
    this.callbacks.push(callback);
  }
  kill(): void {
    this.killed = true;
  }
  exit(code: number | null): void {
    for (const callback of this.callbacks) callback(code);
  }
}

interface Spawned {
  readonly name: string;
  readonly env: Record<string, string>;
  readonly child: FakeChild;
}

function harness(
  overrides: Partial<FederationDemoDeps> & {
    readonly story?: (deps: StoryDeps) => Promise<StoryResult>;
  } = {},
) {
  const lines: string[] = [];
  const spawned: Spawned[] = [];
  const cleaned: string[] = [];
  let storyDeps: StoryDeps | undefined;
  let counter = 0;
  const deps: FederationDemoDeps = {
    store,
    clock,
    out: (line) => lines.push(line),
    spawn: (script, { env }) => {
      const child = new FakeChild();
      spawned.push({ name: script.split("/").slice(-3, -2)[0] ?? "", env, child });
      return child;
    },
    fetch: (async () => new Response("ok", { status: 200 })) as typeof fetch,
    sleep: async () => {},
    isPortFree: async () => true,
    randomHex: (bytes) => {
      counter += 1;
      return String(counter).padStart(2, "0").repeat(bytes);
    },
    baseEnv: {
      PATH: "/usr/bin",
      AUDIT_URL: "http://leftover",
      REVOCATION_SIGNING_SEED: "ab".repeat(32),
    },
    databaseUrl,
    repoRoot: "/repo",
    waitForStep: async () => {},
    makeWorkDir: async () => "/tmp/work",
    cleanupWorkDir: async (dir) => void cleaned.push(dir),
    runStory: (storyArgs) => {
      storyDeps = storyArgs;
      return (overrides.story ?? (() => new Promise<StoryResult>(() => undefined)))(storyArgs);
    },
    ...overrides,
  };
  return { deps, lines, spawned, cleaned, story: () => storyDeps };
}

const running: DemoHandle[] = [];
afterEach(async () => {
  for (const handle of running.splice(0)) await handle.stop();
});

async function begin(deps: FederationDemoDeps): Promise<DemoHandle> {
  const handle = await startFederationDemo(deps);
  running.push(handle);
  return handle;
}

/** The keys created since `before` was taken: the database is shared with other runs. */
async function newDemoKeys(before: ReadonlySet<string>) {
  return (await store.list()).filter(
    (k) => k.name.startsWith("federation-demo-") && !before.has(k.id),
  );
}

async function existingIds(): Promise<Set<string>> {
  return new Set((await store.list()).map((k) => k.id));
}

const settled = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("custos-admin demo-federation: processes", () => {
  it("starts B's audit, A's revocation and identity, then the dashboard, and points A's audit nowhere", async () => {
    const { deps, spawned } = harness();
    await begin(deps);
    expect(spawned.map((s) => s.name)).toEqual(["audit", "revocation", "identity", "dashboard"]);
    const env = (name: string) => spawned.find((s) => s.name === name)?.env ?? {};
    // A's services must not write into B's audit log.
    expect(env("identity")["AUDIT_URL"]).toBe("http://127.0.0.1:9");
    expect(env("revocation")["AUDIT_URL"]).toBe("http://127.0.0.1:9");
    // B's audit service gets no leftover from the shell.
    expect(env("audit")["AUDIT_URL"]).toBeUndefined();
    // A fresh revocation seed, not the one left in the shell.
    expect(env("revocation")["REVOCATION_SIGNING_SEED"]).not.toBe("ab".repeat(32));
    expect(env("revocation")["REVOCATION_SIGNING_SEED"]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses to start when the static host's port is taken", async () => {
    const { deps, spawned } = harness({ isPortFree: async (port) => port !== HOST_PORT });
    await expect(startFederationDemo(deps)).rejects.toThrow(`port ${HOST_PORT} already in use`);
    expect(spawned).toEqual([]);
  });

  it("hands the story A's publisher seed, A's operator key and B's own audit key, and prints none of them", async () => {
    const { deps, lines, story, spawned } = harness();
    await begin(deps);
    const handed = story();
    expect(handed?.revocationSigningSeedHex).toBe(
      spawned.find((s) => s.name === "revocation")?.env["REVOCATION_SIGNING_SEED"],
    );
    expect(handed?.operatorKey).toMatch(/^custos_operator_/);
    expect(handed?.bAuditServiceKey).toMatch(/^custos_service_/);
    expect(handed?.bAuditServiceKey).not.toBe(
      spawned.find((s) => s.name === "identity")?.env["IDENTITY_SERVICE_KEY"],
    );
    const printed = lines.join("\n");
    for (const secret of [
      handed?.revocationSigningSeedHex,
      handed?.operatorKey,
      handed?.bAuditServiceKey,
    ]) {
      expect(printed).not.toContain(secret);
    }
  });

  it("switching A off kills only A's processes and keeps the demo running", async () => {
    const { deps, spawned, story } = harness();
    const handle = await begin(deps);
    let finished = false;
    void handle.finished.then(() => (finished = true));

    const stopping = story()?.stopA();
    for (const s of spawned.filter((s) => s.name === "identity" || s.name === "revocation")) {
      expect(s.child.killed).toBe(true);
      s.child.exit(null);
    }
    await stopping;
    await settled();

    expect(spawned.find((s) => s.name === "audit")?.child.killed).toBe(false);
    expect(spawned.find((s) => s.name === "dashboard")?.child.killed).toBe(false);
    expect(finished).toBe(false);
  });

  it("any other process dying ends the demo, revoking its keys", async () => {
    const before = await existingIds();
    const { deps, spawned, lines } = harness();
    const handle = await begin(deps);
    spawned.find((s) => s.name === "audit")?.child.exit(1);
    expect(await handle.finished).toBe("a service stopped unexpectedly");
    expect(lines.join("\n")).toContain("audit stopped unexpectedly");
    expect(spawned.every((s) => s.child.killed)).toBe(true);
    const keys = await newDemoKeys(before);
    expect(keys).toHaveLength(4);
    expect(keys.every((k) => k.revokedAt !== null)).toBe(true);
  });

  it("when the story ends, stops everything, revokes the keys and removes its work directory", async () => {
    const before = await existingIds();
    const { deps, spawned, cleaned } = harness({ story: async () => ({ refusedAfterMs: 120 }) });
    const handle = await begin(deps);
    expect(await handle.finished).toBe("stopped");
    expect(spawned.every((s) => s.child.killed)).toBe(true);
    expect(cleaned).toEqual(["/tmp/work"]);
    expect((await newDemoKeys(before)).every((k) => k.revokedAt !== null)).toBe(true);
  });

  it("a failing story is reported and ends the demo", async () => {
    const { deps, lines } = harness({ story: async () => Promise.reject(new Error("boom")) });
    const handle = await begin(deps);
    expect(await handle.finished).toBe("the story failed");
    expect(lines).toContain("demo failed: boom");
  });

  it("stop() (Ctrl-C) tells the story to stop before killing the processes", async () => {
    const { deps, story } = harness();
    const handle = await begin(deps);
    const signal = story()?.signal;
    expect(signal?.aborted).toBe(false);
    await handle.stop();
    expect(signal?.aborted).toBe(true);
  });

  it("is reachable as custos-admin demo-federation", async () => {
    const demoFederation = vi.fn(async () => {});
    await runAdminCli(["node", "custos-admin", "demo-federation"], {
      store,
      clock,
      out: () => {},
      demoFederation,
    });
    expect(demoFederation).toHaveBeenCalledOnce();
  });
});

import { createApiKeyStore } from "@custos/control-plane-auth";
import { fixedClock } from "@custos/testing";
import { drizzle } from "drizzle-orm/node-postgres";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { runAdminCli } from "./admin.js";
import {
  DEMO_KEY_LIFETIME_MS,
  buildServiceEnv,
  startDemo,
  type DemoChild,
  type DemoDeps,
} from "./demo.js";

// Against real Postgres from Docker Compose (CLAUDE.md §7): the demo's API
// keys are real rows, so their creation, expiry and revocation are real too.
const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = drizzle(databaseUrl);
const store = createApiKeyStore(db);
const clock = fixedClock("2026-10-12T12:00:00.000Z");

afterAll(async () => {
  await db.$client.end();
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

interface Spawned {
  readonly script: string;
  readonly cwd: string;
  readonly env: Record<string, string>;
  readonly child: FakeChild;
}

class FakeChild implements DemoChild {
  killed = false;
  private exitCallbacks: Array<(code: number | null) => void> = [];
  onExit(callback: (code: number | null) => void): void {
    this.exitCallbacks.push(callback);
  }
  kill(): void {
    this.killed = true;
  }
  exit(code: number | null): void {
    for (const callback of this.exitCallbacks) callback(code);
  }
}

function harness(
  overrides: Partial<DemoDeps> & { readonly serving?: (port: number, n: number) => boolean } = {},
) {
  const events: string[] = [];
  const lines: string[] = [];
  const spawned: Spawned[] = [];
  const seeded: Array<{ tool: string; authorization: string }> = [];
  const polls = new Map<number, number>();
  let counter = 0;

  const deps: DemoDeps = {
    store,
    clock,
    out: (line) => lines.push(line),
    spawn: (script, { cwd, env }) => {
      const child = new FakeChild();
      spawned.push({ script, cwd, env, child });
      events.push(`spawn ${script.split("/").slice(-3, -2)[0]}`);
      return child;
    },
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input));
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { tool: string };
        seeded.push({
          tool: body.tool,
          authorization: (init.headers as Record<string, string>)["authorization"] ?? "",
        });
        return new Response(null, { status: 201 });
      }
      const port = Number(url.port);
      const n = (polls.get(port) ?? 0) + 1;
      polls.set(port, n);
      events.push(`poll ${port}`);
      if (overrides.serving && !overrides.serving(port, n)) throw new Error("ECONNREFUSED");
      return new Response("ok", { status: 200 });
    }) as typeof fetch,
    sleep: async () => {},
    isPortFree: async () => true,
    randomHex: (bytes) => {
      counter += 1;
      return String(counter).padStart(2, "0").repeat(bytes);
    },
    baseEnv: { SystemRoot: "C:\\Windows", PATH: "/usr/bin" },
    databaseUrl,
    repoRoot: "/repo",
    ...overrides,
  };
  return { deps, events, lines, spawned, seeded };
}

async function demoKeys(): Promise<Array<{ revokedAt: Date | null; expiresAt: Date }>> {
  return (await store.list()).filter((k) => k.name.startsWith("demo-"));
}

describe("custos-admin demo", () => {
  it("starts the five services in dependency order, each only after the last is ready", async () => {
    const { deps, events } = harness();
    const handle = await startDemo(deps);

    const order = events.filter((e) => e.startsWith("spawn")).map((e) => e.split(" ")[1]);
    expect(order).toEqual(["audit", "revocation", "identity", "vault", "dashboard"]);
    // each service is polled before the next one is spawned
    const spawnIndex = (name: string) => events.indexOf(`spawn ${name}`);
    expect(events.indexOf("poll 4004")).toBeGreaterThan(spawnIndex("audit"));
    expect(events.indexOf("poll 4004")).toBeLessThan(spawnIndex("revocation"));
    expect(events.indexOf("poll 4003")).toBeLessThan(spawnIndex("identity"));
    expect(events.indexOf("poll 4001")).toBeLessThan(spawnIndex("vault"));
    expect(events.indexOf("poll 4002")).toBeLessThan(spawnIndex("dashboard"));
    await handle.stop();
  });

  it("stores the two stand-in tools using the operator key", async () => {
    const { deps, seeded, spawned } = harness();
    const handle = await startDemo(deps);

    expect(seeded.map((s) => s.tool)).toEqual(["mock-database", "mock-slack"]);
    for (const s of seeded) expect(s.authorization).toMatch(/^Bearer custos_operator_/);
    // the operator key is not given to any service
    for (const s of spawned) expect(JSON.stringify(s.env)).not.toContain("custos_operator_");
    await handle.stop();
  });

  describe("what each service is given", () => {
    it("gives each service only its own secrets, and no secret on a command line", async () => {
      const { deps, spawned } = harness();
      const handle = await startDemo(deps);
      const envOf = (name: string) => spawned.find((s) => s.script.includes(`/${name}/`))!.env;

      expect(Object.keys(envOf("audit")).filter((k) => /SEED|MASTER|SERVICE_KEY/.test(k))).toEqual(
        [],
      );
      expect(envOf("revocation")).toHaveProperty("REVOCATION_SIGNING_SEED");
      expect(envOf("revocation")).toHaveProperty("REVOCATION_SERVICE_KEY");
      expect(envOf("revocation")).not.toHaveProperty("VAULT_MASTER_KEY");
      expect(envOf("revocation")).not.toHaveProperty("IDENTITY_ISSUER_SEED");
      expect(envOf("identity")).toHaveProperty("IDENTITY_ISSUER_SEED");
      expect(envOf("identity")).not.toHaveProperty("VAULT_MASTER_KEY");
      expect(envOf("identity")).not.toHaveProperty("REVOCATION_SIGNING_SEED");
      expect(envOf("vault")).toHaveProperty("VAULT_MASTER_KEY");
      expect(envOf("vault")).not.toHaveProperty("IDENTITY_ISSUER_SEED");
      expect(Object.keys(envOf("dashboard")).filter((k) => /SEED|MASTER|KEY/.test(k))).toEqual([]);
      // the scripts take no arguments, so nothing secret is in argv
      for (const s of spawned)
        expect(s.script).toMatch(/^\/repo\/(services|apps)\/\w+\/dist\/index\.js$/);
      await handle.stop();
    });

    it("pins each port and the database, and keeps what the OS needs", async () => {
      const { deps, spawned } = harness();
      const handle = await startDemo(deps);

      const ports = Object.fromEntries(spawned.map((s) => [s.cwd.split("/").pop(), s.env["PORT"]]));
      expect(ports).toEqual({
        audit: "4004",
        revocation: "4003",
        identity: "4001",
        vault: "4002",
        dashboard: "4005",
      });
      for (const s of spawned) {
        expect(s.env["DATABASE_URL"]).toBe(databaseUrl);
        expect(s.env["SystemRoot"]).toBe("C:\\Windows");
      }
      await handle.stop();
    });

    it("drops leftovers from earlier sessions that would clash with the new keys", () => {
      const env = buildServiceEnv(
        { name: "vault", dir: "services/vault", port: 4002, readyPath: "/health" },
        {
          baseEnv: {
            VAULT_MTLS_CERT: "old.crt",
            VAULT_SERVICE_KEY: "custos_service_old",
            REVOCATION_SERVICE_KEY: "custos_service_other",
            CUSTOS_OPERATOR_KEY: "custos_operator_old",
            MTLS_CA: "ca.crt",
            PORT: "9999",
            DATABASE_URL: "postgres://elsewhere",
            PATH: "/usr/bin",
          },
          databaseUrl: "postgres://here",
          keys: { VAULT_SERVICE_KEY: "custos_service_new" },
          seeds: { VAULT_MASTER_KEY: "aa".repeat(32) },
        },
      );

      expect(env).toEqual({
        PATH: "/usr/bin",
        PORT: "4002",
        DATABASE_URL: "postgres://here",
        VAULT_SERVICE_KEY: "custos_service_new",
        VAULT_MASTER_KEY: "aa".repeat(32),
      });
    });
  });

  describe("seeds", () => {
    it("reuses valid seeds from the environment so earlier credentials keep verifying", async () => {
      const issuer = "ab".repeat(32);
      const { deps, spawned } = harness({
        baseEnv: { IDENTITY_ISSUER_SEED: issuer, VAULT_MASTER_KEY: "cd".repeat(32) },
      });
      const handle = await startDemo(deps);

      const envOf = (name: string) => spawned.find((s) => s.script.includes(`/${name}/`))!.env;
      expect(envOf("identity")["IDENTITY_ISSUER_SEED"]).toBe(issuer);
      expect(envOf("vault")["VAULT_MASTER_KEY"]).toBe("cd".repeat(32));
      // the one not supplied is generated
      expect(envOf("revocation")["REVOCATION_SIGNING_SEED"]).toMatch(/^[0-9a-f]{64}$/);
      await handle.stop();
    });

    it("replaces a malformed seed instead of passing it on", async () => {
      const { deps, spawned } = harness({ baseEnv: { IDENTITY_ISSUER_SEED: "not-hex" } });
      const handle = await startDemo(deps);

      const identity = spawned.find((s) => s.script.includes("/identity/"))!;
      expect(identity.env["IDENTITY_ISSUER_SEED"]).toMatch(/^[0-9a-f]{64}$/);
      await handle.stop();
    });

    it("never prints a seed, a service key, or the master key", async () => {
      const { deps, lines, spawned } = harness();
      const handle = await startDemo(deps);

      const printed = lines.join("\n");
      for (const s of spawned) {
        for (const name of [
          "IDENTITY_ISSUER_SEED",
          "REVOCATION_SIGNING_SEED",
          "VAULT_MASTER_KEY",
          "IDENTITY_SERVICE_KEY",
          "REVOCATION_SERVICE_KEY",
          "VAULT_SERVICE_KEY",
        ]) {
          const value = s.env[name];
          if (value !== undefined) expect(printed).not.toContain(value);
        }
      }
      expect(printed).toMatch(/CUSTOS_OPERATOR_KEY=custos_operator_/);
      await handle.stop();
    });
  });

  describe("demo API keys", () => {
    it("expires them in 12 hours and revokes them on stop", async () => {
      const { deps } = harness();
      const handle = await startDemo(deps);
      const during = (await demoKeys()).filter((k) => k.revokedAt === null);

      expect(during.length).toBeGreaterThanOrEqual(4);
      for (const k of during) {
        expect(k.expiresAt.getTime()).toBe(clock.now().getTime() + DEMO_KEY_LIFETIME_MS);
      }

      await handle.stop();

      expect((await demoKeys()).filter((k) => k.revokedAt === null)).toEqual([]);
      expect(await handle.finished).toBe("stopped");
    });

    it("kills every service on stop, and stop is safe to repeat", async () => {
      const { deps, spawned } = harness();
      const handle = await startDemo(deps);

      await handle.stop();
      await handle.stop();

      expect(spawned).toHaveLength(5);
      expect(spawned.every((s) => s.child.killed)).toBe(true);
    });
  });

  describe("when something is wrong", () => {
    it("refuses to start if a port is taken, before touching anything", async () => {
      const keysBefore = (await demoKeys()).length;
      const { deps, spawned } = harness({ isPortFree: async (port) => port !== 4002 });

      await expect(startDemo(deps)).rejects.toThrow(/port 4002 already in use/);

      expect(spawned).toEqual([]);
      expect((await demoKeys()).length).toBe(keysBefore);
    });

    it("names every busy port", async () => {
      const { deps } = harness({ isPortFree: async (port) => port > 4004 || port < 4002 });

      await expect(startDemo(deps)).rejects.toThrow(/ports 4002, 4003, 4004 already in use/);
    });

    it("stops everything and says which service failed if one never answers", async () => {
      const { deps, spawned } = harness({ serving: (port) => port !== 4002 });

      await expect(startDemo(deps)).rejects.toThrow(/vault did not start \(port 4002\)/);

      expect(spawned.map((s) => s.child.killed)).toEqual([true, true, true, true]);
      expect((await demoKeys()).filter((k) => k.revokedAt === null)).toEqual([]);
    });

    it("does not mistake an older process on the port for a healthy new one", async () => {
      // The port answers (an old run still holds it) but the new process exits.
      const { deps, spawned } = harness();
      const original = deps.spawn;
      const wrapped: DemoDeps = {
        ...deps,
        spawn: (script, options) => {
          const child = original(script, options) as FakeChild;
          if (script.includes("/identity/")) queueMicrotask(() => child.exit(1));
          return child;
        },
      };

      await expect(startDemo(wrapped)).rejects.toThrow(/identity did not start/);
      expect(spawned.every((s) => s.child.killed)).toBe(true);
    });

    it("shuts the rest down if a service dies after start-up", async () => {
      const { deps, spawned, lines } = harness();
      const handle = await startDemo(deps);

      spawned.find((s) => s.script.includes("/vault/"))!.child.exit(137);

      expect(await handle.finished).toBe("stopped");
      expect(lines.join("\n")).toMatch(/vault stopped unexpectedly \(exit 137\)/);
      expect(spawned.every((s) => s.child.killed)).toBe(true);
      expect((await demoKeys()).filter((k) => k.revokedAt === null)).toEqual([]);
    });

    it("stops everything if the vault refuses a tool credential", async () => {
      const { deps, spawned } = harness();
      const failing: DemoDeps = {
        ...deps,
        fetch: (async (input: string | URL | Request, init?: RequestInit) =>
          init?.method === "POST"
            ? new Response(null, { status: 401 })
            : deps.fetch(input, init)) as typeof fetch,
      };

      await expect(startDemo(failing)).rejects.toThrow(/seeding mock-database failed.*401/);

      expect(spawned.every((s) => s.child.killed)).toBe(true);
    });
  });

  describe("the command", () => {
    it("runs the demo through custos-admin", async () => {
      const demo = vi.fn(async () => {});
      await runAdminCli(["node", "custos-admin", "demo"], {
        store,
        clock,
        out: () => {},
        demo,
      });
      expect(demo).toHaveBeenCalledOnce();
    });

    it("fails with one error line where no demo is wired in", async () => {
      let stderr = "";
      vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
        stderr += String(chunk);
        return true;
      });

      await runAdminCli(["node", "custos-admin", "demo"], { store, clock, out: () => {} });

      expect(stderr).toContain("the demo is not available here");
      expect(process.exitCode).toBe(1);
    });
  });
});

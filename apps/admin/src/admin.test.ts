import { randomUUID } from "node:crypto";
import { createApiKeyAuthenticator, createApiKeyStore } from "@custos/control-plane-auth";
import { fixedClock } from "@custos/testing";
import { drizzle } from "drizzle-orm/node-postgres";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { parseDuration, runAdminCli } from "./admin.js";

// Against real Postgres from Docker Compose (CLAUDE.md §7).
const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = drizzle(databaseUrl);
const store = createApiKeyStore(db);
const clock = fixedClock("2026-10-02T12:00:00.000Z");

afterAll(async () => {
  await db.$client.end();
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

async function run(...args: string[]): Promise<{ lines: string[]; stderr: string }> {
  const lines: string[] = [];
  let stderr = "";
  vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
    stderr += String(chunk);
    return true;
  });
  await runAdminCli(["node", "custos-admin", ...args], {
    store,
    clock,
    out: (line) => lines.push(line),
  });
  return { lines, stderr };
}

function tokenFrom(lines: string[]): string {
  const line = lines.find((l) => l.startsWith("key: "));
  if (!line) throw new Error("no key printed");
  return line.slice("key: ".length);
}

describe("custos-admin key", () => {
  it("creates an operator key that authenticates, prints it once, lists it, then revokes it", async () => {
    const name = `admin-test-${randomUUID()}`;
    const created = await run(
      "key",
      "create",
      "--kind",
      "operator",
      "--name",
      name,
      "--scopes",
      "agents:register, policies:write",
      "--expires-in",
      "30d",
    );
    expect(process.exitCode).toBeUndefined();
    const token = tokenFrom(created.lines);
    const id = created.lines[0]!.replace("id:  ", "");

    const authenticator = createApiKeyAuthenticator({ keys: store, clock });
    const auth = await authenticator.authenticate({
      headers: { authorization: `Bearer ${token}` },
    });
    expect(auth.ok && [...auth.value.scopes].sort()).toEqual(["agents:register", "policies:write"]);
    expect((await store.findById(id))?.expiresAt).toEqual(new Date("2026-11-01T12:00:00.000Z"));

    const listed = await run("key", "list");
    const row = listed.lines.find((line) => line.startsWith(id));
    expect(row).toContain("\toperator\tactive\t");
    expect(listed.lines.join("\n")).not.toContain(token);

    const revoked = await run("key", "revoke", id);
    expect(revoked.lines).toEqual([`revoked ${id}`]);
    expect((await run("key", "list")).lines.find((l) => l.startsWith(id))).toContain("\trevoked\t");
    const after = await authenticator.authenticate({
      headers: { authorization: `Bearer ${token}` },
    });
    expect(after.ok).toBe(false);
  });

  it("defaults to a 90-day expiry", async () => {
    const created = await run(
      "key",
      "create",
      "--kind",
      "service",
      "--name",
      `svc-${randomUUID()}`,
      "--scopes",
      "audit:write",
    );
    const id = created.lines[0]!.replace("id:  ", "");
    expect((await store.findById(id))?.expiresAt).toEqual(new Date("2026-12-31T12:00:00.000Z"));
  });

  it("refuses a service-only scope on an operator key, creating nothing", async () => {
    const name = `admin-test-${randomUUID()}`;
    const result = await run(
      "key",
      "create",
      "--kind",
      "operator",
      "--name",
      name,
      "--scopes",
      "audit:write",
    );
    expect(process.exitCode).toBe(1);
    expect(result.stderr).toContain("SCOPE_NOT_ALLOWED: audit:write");
    expect(result.lines).toEqual([]);
    expect((await store.list()).some((key) => key.name === name)).toBe(false);
  });

  it("refuses an unknown kind", async () => {
    await run("key", "create", "--kind", "agent", "--name", "x", "--scopes", "audit:write");
    expect(process.exitCode).toBe(1);
  });

  it("reports revoking an unknown key", async () => {
    const result = await run("key", "revoke", "0000000000000000");
    expect(process.exitCode).toBe(1);
    expect(result.stderr).toContain("no such key");
  });

  it("shows an expired key as expired", async () => {
    const name = `admin-test-${randomUUID()}`;
    const created = await store.create({
      kind: "operator",
      name,
      scopes: ["agents:revoke"],
      expiresAt: new Date("2026-10-02T12:00:01.000Z"),
      now: new Date("2026-10-01T00:00:00.000Z"),
    });
    if (!created.ok) throw new Error("setup failed");
    const lines = (await run("key", "list")).lines;
    expect(lines.find((l) => l.startsWith(created.id))).toContain("\tactive\t");
    const later = fixedClock("2026-10-02T12:00:01.000Z");
    const out: string[] = [];
    await runAdminCli(["node", "custos-admin", "key", "list"], {
      store,
      clock: later,
      out: (line) => out.push(line),
    });
    expect(out.find((l) => l.startsWith(created.id))).toContain("\texpired\t");
  });

  it("prints help without failing", async () => {
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    await run("--help");
    expect(process.exitCode).toBeUndefined();
  });
});

describe("parseDuration", () => {
  it("parses days and hours", () => {
    expect(parseDuration("90d")).toBe(90 * 24 * 3_600_000);
    expect(parseDuration("12h")).toBe(12 * 3_600_000);
  });

  it.each(["0d", "90", "1w", "-1d", "1.5d", "999999d", ""])("rejects %j", (value) => {
    expect(() => parseDuration(value)).toThrow(/expected a duration/);
  });
});

describe("custos-admin dev-keys", () => {
  async function devKeys(...args: string[]): Promise<Map<string, string>> {
    const { lines } = await run("dev-keys", ...args);
    expect(process.exitCode).toBeUndefined();
    const assignments = new Map<string, string>();
    for (const line of lines) {
      const match = /^(?:export (\w+)=(\S+)|\$env:(\w+) = "(\S+)")$/.exec(line);
      if (match) assignments.set((match[1] ?? match[3])!, (match[2] ?? match[4])!);
      else expect(line.startsWith("# ")).toBe(true);
    }
    return assignments;
  }

  it("creates an operator key and the three service keys, each with exactly its scopes", async () => {
    const keys = await devKeys();
    expect([...keys.keys()]).toEqual([
      "CUSTOS_OPERATOR_KEY",
      "IDENTITY_SERVICE_KEY",
      "REVOCATION_SERVICE_KEY",
      "VAULT_SERVICE_KEY",
    ]);
    const authenticator = createApiKeyAuthenticator({ keys: store, clock });
    const scopesOf = async (variable: string) => {
      const result = await authenticator.authenticate({
        headers: { authorization: `Bearer ${keys.get(variable)}` },
      });
      if (!result.ok) throw new Error(`${variable} did not authenticate`);
      return { kind: result.value.kind, scopes: [...result.value.scopes].sort() };
    };
    expect(await scopesOf("CUSTOS_OPERATOR_KEY")).toEqual({
      kind: "operator",
      scopes: [
        "agents:read",
        "agents:register",
        "agents:revoke",
        "audit:read",
        "credentials:write",
        "policies:read",
        "policies:write",
        "revocations:read",
      ],
    });
    expect(await scopesOf("IDENTITY_SERVICE_KEY")).toEqual({
      kind: "service",
      scopes: ["audit:write", "status:allocate"],
    });
    expect(await scopesOf("REVOCATION_SERVICE_KEY")).toEqual({
      kind: "service",
      scopes: ["audit:write"],
    });
    expect(await scopesOf("VAULT_SERVICE_KEY")).toEqual({
      kind: "service",
      scopes: ["audit:write"],
    });
  });

  describe("--check (ADR 0022 §3: recreate keys that lack a scope)", () => {
    async function check(env: Record<string, string | undefined>) {
      const lines: string[] = [];
      let stderr = "";
      vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
        stderr += String(chunk);
        return true;
      });
      await runAdminCli(["node", "custos-admin", "dev-keys", "--check"], {
        // --check only reads: a create would fail the run.
        store: {
          ...store,
          create: async () => {
            throw new Error("dev-keys --check created a key");
          },
        },
        clock,
        out: (line) => lines.push(line),
        env,
      });
      const exitCode = process.exitCode;
      process.exitCode = undefined;
      return { lines, stderr, exitCode };
    }

    it("passes a fresh set, prints no key and creates nothing", async () => {
      const keys = Object.fromEntries(await devKeys());
      const { lines, stderr, exitCode } = await check(keys);
      expect(exitCode).toBeUndefined();
      expect(lines).toEqual([
        "# CUSTOS_OPERATOR_KEY: ok",
        "# IDENTITY_SERVICE_KEY: ok",
        "# REVOCATION_SERVICE_KEY: ok",
        "# VAULT_SERVICE_KEY: ok",
      ]);
      for (const token of Object.values(keys)) {
        expect(lines.join("\n") + stderr).not.toContain(token);
      }
    });

    it("fails an operator key made before the read scopes, naming what it lacks", async () => {
      const keys = Object.fromEntries(await devKeys());
      const old = await store.create({
        kind: "operator",
        name: `pre-read-scopes-${randomUUID()}`,
        scopes: ["credentials:write", "policies:write", "agents:revoke", "agents:register"],
        expiresAt: new Date(clock.now().getTime() + 86_400_000),
        now: clock.now(),
      });
      if (!old.ok) throw new Error("test setup: key not created");
      const { lines, stderr, exitCode } = await check({ ...keys, CUSTOS_OPERATOR_KEY: old.token });
      expect(exitCode).toBe(1);
      expect(lines[0]).toBe(
        "# CUSTOS_OPERATOR_KEY: lacks audit:read, revocations:read, policies:read, agents:read",
      );
      expect(lines.slice(1).every((line) => line.endsWith(": ok"))).toBe(true);
      expect(stderr).toContain("dev keys need recreating: CUSTOS_OPERATOR_KEY");
      expect(lines.join("\n") + stderr).not.toContain(old.token);
    });

    it("fails a revoked, an unset, an unknown and a wrong-kind key", async () => {
      const keys = Object.fromEntries(await devKeys());
      const revoked = keys.VAULT_SERVICE_KEY!;
      const revokedId = /^custos_service_([0-9a-f]{16})_/.exec(revoked)?.[1];
      expect(await store.revoke(revokedId!, clock.now())).toBe(true);
      const { lines, stderr, exitCode } = await check({
        CUSTOS_OPERATOR_KEY: keys.IDENTITY_SERVICE_KEY,
        IDENTITY_SERVICE_KEY: undefined,
        REVOCATION_SERVICE_KEY: "custos_service_0123456789abcdef_" + "x".repeat(43),
        VAULT_SERVICE_KEY: revoked,
      });
      expect(exitCode).toBe(1);
      expect(lines[0]).toBe("# CUSTOS_OPERATOR_KEY: is a service key, needs operator");
      expect(lines.slice(1)).toEqual([
        "# IDENTITY_SERVICE_KEY: not set",
        "# REVOCATION_SERVICE_KEY: not usable (UNKNOWN_KEY)",
        "# VAULT_SERVICE_KEY: not usable (REVOKED)",
      ]);
      expect(stderr).toContain(
        "dev keys need recreating: CUSTOS_OPERATOR_KEY, IDENTITY_SERVICE_KEY, REVOCATION_SERVICE_KEY, VAULT_SERVICE_KEY",
      );
    });
  });

  it("prints PowerShell assignments on request", async () => {
    const keys = await devKeys("--shell", "powershell");
    expect(keys.get("VAULT_SERVICE_KEY")).toMatch(/^custos_service_/);
  });

  it("rejects an unknown shell", async () => {
    await run("dev-keys", "--shell", "fish");
    expect(process.exitCode).toBe(1);
  });

  it("reports a key the store refuses", async () => {
    const lines: string[] = [];
    let stderr = "";
    vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderr += String(chunk);
      return true;
    });
    await runAdminCli(["node", "custos-admin", "dev-keys"], {
      store: { ...store, create: async () => ({ ok: false, error: { code: "NO_SCOPES" } }) },
      clock,
      out: (line) => lines.push(line),
    });
    expect(process.exitCode).toBe(1);
    expect(stderr).toContain("dev key dev-operator not created — NO_SCOPES");
  });
});

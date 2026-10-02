import { randomUUID } from "node:crypto";
import { fixedClock } from "@custos/testing";
import { drizzle } from "drizzle-orm/node-postgres";
import { afterAll, describe, expect, it } from "vitest";
import { createApiKeyAuthenticator } from "./authenticator.js";
import { createApiKeyStore } from "./store.js";

// Integration: real Postgres from Docker Compose, never a mock (CLAUDE.md §7).
const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = drizzle(databaseUrl);
const store = createApiKeyStore(db);

afterAll(async () => {
  await db.$client.end();
});

const now = new Date("2026-10-02T12:00:00.000Z");
const later = new Date("2026-12-31T00:00:00.000Z");
const uniqueName = (): string => `test-${randomUUID()}`;

describe("createApiKeyStore (Postgres)", () => {
  it("creates a key that then authenticates, storing only its hash", async () => {
    const name = uniqueName();
    const created = await store.create({
      kind: "operator",
      name,
      scopes: ["agents:register", "agents:register"],
      expiresAt: later,
      now,
    });
    expect(created.ok).toBe(true);
    if (!created.ok) return;

    const row = await store.findById(created.id);
    expect(row?.scopes).toEqual(["agents:register"]);
    expect(row?.secretHash).toMatch(/^[0-9a-f]{64}$/);
    expect(created.token).not.toContain(row!.secretHash);
    expect(JSON.stringify(row)).not.toContain(created.token.slice(-43));

    const authenticator = createApiKeyAuthenticator({ keys: store, clock: fixedClock(now) });
    const result = await authenticator.authenticate({
      headers: { authorization: `Bearer ${created.token}` },
    });
    expect(result.ok && result.value.name).toBe(name);
  });

  it("lists keys without their hashes", async () => {
    const created = await store.create({
      kind: "service",
      name: uniqueName(),
      scopes: ["audit:write"],
      expiresAt: later,
      now,
    });
    const listed = (await store.list()).find((key) => created.ok && key.id === created.id);
    expect(listed).toMatchObject({ kind: "service", scopes: ["audit:write"], revokedAt: null });
    expect(listed).not.toHaveProperty("secretHash");
  });

  it("revokes a key, which then fails authentication; the first revocation time sticks", async () => {
    const created = await store.create({
      kind: "operator",
      name: uniqueName(),
      scopes: ["agents:revoke"],
      expiresAt: later,
      now,
    });
    if (!created.ok) throw new Error("setup failed");
    const firstRevocation = new Date("2026-10-02T13:00:00.000Z");
    expect(await store.revoke(created.id, firstRevocation)).toBe(true);
    expect(await store.revoke(created.id, new Date("2026-10-02T14:00:00.000Z"))).toBe(true);
    expect((await store.findById(created.id))?.revokedAt).toEqual(firstRevocation);

    const authenticator = createApiKeyAuthenticator({ keys: store, clock: fixedClock(now) });
    const result = await authenticator.authenticate({
      headers: { authorization: `Bearer ${created.token}` },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toBe("REVOKED");
  });

  it("reports revoking an unknown key", async () => {
    expect(await store.revoke("0000000000000000", now)).toBe(false);
  });

  it.each([
    [{ name: "  " }, { code: "INVALID_NAME" }],
    [{ name: "x".repeat(101) }, { code: "INVALID_NAME" }],
    [{ scopes: [] }, { code: "NO_SCOPES" }],
    [{ scopes: ["root"] }, { code: "UNKNOWN_SCOPE", scope: "root" }],
    [{ scopes: ["audit:write"] }, { code: "SCOPE_NOT_ALLOWED", scope: "audit:write" }],
    [{ scopes: ["status:allocate"] }, { code: "SCOPE_NOT_ALLOWED", scope: "status:allocate" }],
    [{ expiresAt: now }, { code: "EXPIRY_NOT_IN_FUTURE" }],
  ])("refuses to create an invalid operator key: %j", async (override, error) => {
    const name = uniqueName();
    const result = await store.create({
      kind: "operator",
      name,
      scopes: ["agents:register"],
      expiresAt: later,
      now,
      ...override,
    });
    expect(result).toEqual({ ok: false, error });
    expect((await store.list()).some((key) => key.name === name)).toBe(false);
  });
});

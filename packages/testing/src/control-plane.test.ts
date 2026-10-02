import { drizzle } from "drizzle-orm/node-postgres";
import { afterAll, describe, expect, it } from "vitest";
import { fixedClock } from "./clock.js";
import { bearer, createTestControlPlane } from "./control-plane.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = drizzle(databaseUrl);
const clock = fixedClock("2026-10-02T12:00:00.000Z");

afterAll(async () => {
  await db.$client.end();
});

describe("createTestControlPlane", () => {
  it("issues a real key its guard accepts", async () => {
    const controlPlane = createTestControlPlane(db, clock);
    const token = await controlPlane.key("service", ["audit:write"]);
    const result = await controlPlane.guard.authenticator.authenticate({ headers: bearer(token) });
    expect(result.ok && result.value.kind).toBe("service");
  });

  it("can issue an already-expired key, which its guard refuses", async () => {
    const controlPlane = createTestControlPlane(db, clock);
    const token = await controlPlane.key("operator", ["policies:write"], {
      expiresAt: new Date("2026-10-01T00:00:00.000Z"),
    });
    const result = await controlPlane.guard.authenticator.authenticate({ headers: bearer(token) });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toBe("EXPIRED");
  });

  it("throws on a key the store refuses", async () => {
    await expect(
      createTestControlPlane(db, clock).key("operator", ["audit:write"]),
    ).rejects.toThrow("SCOPE_NOT_ALLOWED");
  });

  it("defaults to the wall clock", async () => {
    const controlPlane = createTestControlPlane(db);
    const token = await controlPlane.key("operator", ["agents:revoke"]);
    const result = await controlPlane.guard.authenticator.authenticate({ headers: bearer(token) });
    expect(result.ok).toBe(true);
  });
});

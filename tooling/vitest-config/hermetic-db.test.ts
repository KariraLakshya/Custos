import pg from "pg";
import { afterEach, describe, expect, it } from "vitest";
import {
  createMigratedTestDatabase,
  dropTestDatabase,
  setup,
  teardown,
  testDatabaseAgeStamp,
  testDatabaseName,
  withDatabase,
} from "./hermetic-db.js";

// This package has no vitest config, and these tests wait behind every other
// package's database setup when the whole repo is tested at once.
const SLOW = 30_000;

const adminUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";

async function withClient<T>(url: string, fn: (c: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

const exists = (name: string): Promise<boolean> =>
  withClient(adminUrl, async (c) => {
    const { rowCount } = await c.query("SELECT 1 FROM pg_database WHERE datname = $1", [name]);
    return rowCount === 1;
  });

describe("name helpers", () => {
  it("round-trips the timestamp", () => {
    expect(testDatabaseAgeStamp(testDatabaseName(1234, "ab12cd34"))).toBe(1234);
  });

  it("does not recognise databases it did not create", () => {
    for (const name of [
      "custos",
      "postgres",
      "custos_test_x_ab",
      "custos_test_12_",
      "other_1_ab",
    ]) {
      expect(testDatabaseAgeStamp(name)).toBeUndefined();
    }
  });

  it("swaps only the database in a URL", () => {
    expect(withDatabase("postgres://u:p@h:5433/custos?sslmode=disable", "x")).toBe(
      "postgres://u:p@h:5433/x?sslmode=disable",
    );
  });
});

describe("hermetic database", () => {
  afterEach(async () => {
    await teardown();
  });

  it(
    "creates a migrated database, points DATABASE_URL at it and drops it afterwards",
    async () => {
      const before = process.env.DATABASE_URL;
      await setup();
      const url = process.env.DATABASE_URL ?? "";
      const name = new URL(url).pathname.slice(1);

      expect(testDatabaseAgeStamp(name)).toBeDefined();
      expect(await exists(name)).toBe(true);
      const tables = await withClient(url, async (c) => {
        const { rows } = await c.query<{ table_name: string }>(
          "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
        );
        return rows.map((r) => r.table_name);
      });
      expect(tables).toEqual(expect.arrayContaining(["agents", "audit_records", "api_keys"]));

      await teardown();
      expect(await exists(name)).toBe(false);
      expect(process.env.DATABASE_URL).toBe(before);
    },
    SLOW,
  );

  it(
    "drops stale test databases left by a killed run, but keeps recent and foreign ones",
    async () => {
      const stale = testDatabaseName(Date.now() - 2 * 60 * 60 * 1000, "deadbeef");
      const recent = testDatabaseName(Date.now(), "cafebabe");
      await withClient(adminUrl, async (c) => {
        await c.query(`CREATE DATABASE "${stale}"`);
        await c.query(`CREATE DATABASE "${recent}"`);
      });
      try {
        await setup();
        expect(await exists(stale)).toBe(false);
        expect(await exists(recent)).toBe(true);
      } finally {
        await withClient(adminUrl, async (c) => {
          await c.query(`DROP DATABASE IF EXISTS "${stale}" WITH (FORCE)`);
          await c.query(`DROP DATABASE IF EXISTS "${recent}" WITH (FORCE)`);
        });
      }
    },
    SLOW,
  );

  it("teardown without setup does nothing", async () => {
    await expect(teardown()).resolves.toBeUndefined();
  });
});

describe("createMigratedTestDatabase", () => {
  it(
    "creates a second migrated database, named so a killed run's leftover is swept, and drops it",
    async () => {
      const { name, url } = await createMigratedTestDatabase(adminUrl);
      try {
        expect(testDatabaseAgeStamp(name)).toBeTypeOf("number");
        expect(await exists(name)).toBe(true);
        const tables = await withClient(url, async (c) => {
          const { rows } = await c.query<{ tablename: string }>(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
          );
          return rows.map((row) => row.tablename);
        });
        expect(tables).toContain("agents");
      } finally {
        await dropTestDatabase(adminUrl, name);
      }
      expect(await exists(name)).toBe(false);
    },
    SLOW,
  );
});

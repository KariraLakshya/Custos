// Vitest global setup: gives one test run its own freshly migrated Postgres
// database and drops it afterwards, so tests never write into (or read the
// history of) the shared dev database. Opt in per package through
// `createVitestConfig({ test: { globalSetup: [hermeticDatabaseSetup] } })`.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import pg from "pg";

export const hermeticDatabaseSetup = fileURLToPath(import.meta.url);

const DEFAULT_URL = "postgres://custos:custos@localhost:5433/custos";
const NAME_PREFIX = "custos_test_";
// A run that was killed before teardown leaves its database behind; the next
// run drops any such database older than this.
const STALE_AFTER_MS = 60 * 60 * 1000;
// Arbitrary constant shared by every run so that they contend for one lock.
const SETUP_LOCK_ID = 7_283_501;
const migrationsFolder = fileURLToPath(new URL("../../infra/migrations", import.meta.url));
const sealStoreFolder = fileURLToPath(new URL("../../infra/seal-store", import.meta.url));

let created: { name: string; adminUrl: string; previous: string | undefined } | undefined;

export function testDatabaseName(nowMs: number, suffix: string): string {
  return `${NAME_PREFIX}${nowMs}_${suffix}`;
}

/** Epoch milliseconds embedded in a test database name, or undefined if it is not one of ours. */
export function testDatabaseAgeStamp(name: string): number | undefined {
  const match = new RegExp(`^${NAME_PREFIX}(\\d+)_[0-9a-f]+$`).exec(name);
  return match?.[1] === undefined ? undefined : Number(match[1]);
}

export function withDatabase(url: string, database: string): string {
  const next = new URL(url);
  next.pathname = `/${database}`;
  return next.toString();
}

// Identifiers can't be bound as parameters. The name is built only from our
// prefix, digits and hex, and quoted anyway.
function quoted(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

async function dropStale(admin: pg.Client, nowMs: number): Promise<void> {
  const { rows } = await admin.query<{ datname: string }>(
    "SELECT datname FROM pg_database WHERE datname LIKE 'custos\\_test\\_%'",
  );
  for (const { datname } of rows) {
    const stamp = testDatabaseAgeStamp(datname);
    if (stamp !== undefined && nowMs - stamp > STALE_AFTER_MS) {
      await admin.query(`DROP DATABASE IF EXISTS ${quoted(datname)} WITH (FORCE)`);
    }
  }
}

/**
 * Creates and migrates one more test database, named like the hermetic one so
 * a killed run's leftover is swept by the next run. For a test that needs a
 * second, independent organisation's database (the Phase 6 two-stack e2e).
 * Returns its URL; drop it with `dropTestDatabase`.
 */
export async function createMigratedTestDatabase(adminUrl: string): Promise<{
  readonly name: string;
  readonly url: string;
}> {
  const name = testDatabaseName(Date.now(), randomBytes(4).toString("hex"));
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    // Packages run their tests in parallel and Postgres refuses overlapping
    // CREATE DATABASE calls (they all copy template1), so setups take turns.
    await admin.query("SELECT pg_advisory_lock($1)", [SETUP_LOCK_ID]);
    await dropStale(admin, Date.now());
    await admin.query(`CREATE DATABASE ${quoted(name)}`);
  } finally {
    await admin.end(); // ends the session, which releases the lock
  }

  const url = withDatabase(adminUrl, name);
  const pool = new pg.Pool({ connectionString: url, max: 1 });
  try {
    await migrate(drizzle(pool), { migrationsFolder });
  } finally {
    await pool.end();
  }
  return { name, url };
}

/**
 * A fresh database set up as an audit seal store (ADR 0017 part 2a), with
 * exactly the SQL a real one gets (`infra/seal-store`), owned by the admin
 * role in `adminUrl`. Returns URLs for the admin, the insert-only
 * `custos_sealer` and the read-only `custos_auditor`. The roles are
 * server-wide and shared by every run (created if missing, under the setup
 * lock); drop the database with `dropTestDatabase`.
 */
export async function createSealStoreTestDatabase(adminUrl: string): Promise<{
  readonly name: string;
  readonly url: string;
  readonly sealerUrl: string;
  readonly auditorUrl: string;
}> {
  const name = testDatabaseName(Date.now(), randomBytes(4).toString("hex"));
  const roles = readFileSync(`${sealStoreFolder}/roles.dev.sql`, "utf8");
  const schema = readFileSync(`${sealStoreFolder}/schema.sql`, "utf8");
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query("SELECT pg_advisory_lock($1)", [SETUP_LOCK_ID]);
    await dropStale(admin, Date.now());
    await admin.query(roles);
    await admin.query(`CREATE DATABASE ${quoted(name)}`);
  } finally {
    await admin.end();
  }
  const url = withDatabase(adminUrl, name);
  const owner = new pg.Client({ connectionString: url });
  await owner.connect();
  try {
    await owner.query(schema);
  } finally {
    await owner.end();
  }
  const as = (user: string) => {
    const next = new URL(url);
    next.username = user;
    next.password = user; // the dev-only passwords in roles.dev.sql
    return next.toString();
  };
  return { name, url, sealerUrl: as("custos_sealer"), auditorUrl: as("custos_auditor") };
}

export async function dropTestDatabase(adminUrl: string, name: string): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${quoted(name)} WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}

export async function setup(): Promise<void> {
  const adminUrl = process.env.DATABASE_URL ?? DEFAULT_URL;
  const { name, url } = await createMigratedTestDatabase(adminUrl);
  created = { name, adminUrl, previous: process.env.DATABASE_URL };
  // Test workers are started after global setup and inherit this.
  process.env.DATABASE_URL = url;
}

export async function teardown(): Promise<void> {
  if (created === undefined) return;
  const { name, adminUrl, previous } = created;
  created = undefined;
  if (previous === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = previous;
  await dropTestDatabase(adminUrl, name);
}

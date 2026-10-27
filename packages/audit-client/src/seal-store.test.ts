import { createSealStoreTestDatabase, dropTestDatabase } from "@custos/vitest-config/hermetic-db";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPostgresSealStore, SealCopyConflictError, type SealStore } from "./seal-store.js";

// ADR 0017 part 2a. A fresh database set up with infra/seal-store's own SQL,
// reached through the real roles: custos_sealer (the audit service) and
// custos_auditor (custos audit-log).
const adminUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
let database: Awaited<ReturnType<typeof createSealStoreTestDatabase>>;
let sealer: SealStore;
let auditor: SealStore;

beforeAll(async () => {
  database = await createSealStoreTestDatabase(adminUrl);
  sealer = createPostgresSealStore(database.sealerUrl);
  auditor = createPostgresSealStore(database.auditorUrl);
});

afterAll(async () => {
  await sealer.close();
  await auditor.close();
  await dropTestDatabase(adminUrl, database.name);
});

/** Runs one statement as `url`'s role and returns the error message, or "ok". */
async function attempt(url: string, statement: string): Promise<string> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query(statement);
    return "ok";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  } finally {
    await client.end();
  }
}

describe("createPostgresSealStore", () => {
  it("stores copies and lists them for one log, oldest first, from a seq", async () => {
    const log = "did:web:audit.a.example";
    await sealer.put({ log, seq: 2, seal: "seal-2" });
    await sealer.put({ log, seq: 1, seal: "seal-1" });
    await sealer.put({ log, seq: 5, seal: "seal-5" });
    await sealer.put({ log: "did:web:audit.b.example", seq: 3, seal: "other-log" });

    expect(await auditor.list(log, 1)).toEqual(["seal-1", "seal-2", "seal-5"]);
    expect(await auditor.list(log, 2)).toEqual(["seal-2", "seal-5"]);
    expect(await auditor.list("did:web:audit.c.example", 1)).toEqual([]);
  });

  it("accepts the same copy again", async () => {
    const log = "did:web:audit.again.example";
    await sealer.put({ log, seq: 1, seal: "seal-1" });
    await expect(sealer.put({ log, seq: 1, seal: "seal-1" })).resolves.toBeUndefined();
  });

  it("refuses a different seal at a position already stored: evidence of a rewrite", async () => {
    const log = "did:web:audit.conflict.example";
    await sealer.put({ log, seq: 1, seal: "original" });
    const result = sealer.put({ log, seq: 1, seal: "rewritten" });
    await expect(result).rejects.toBeInstanceOf(SealCopyConflictError);
    expect(await auditor.list(log, 1)).toEqual(["original"]);
  });

  it("throws when the store cannot be reached, for the caller to fail closed", async () => {
    const down = createPostgresSealStore("postgres://custos_auditor:x@127.0.0.1:1/none");
    await expect(down.list("did:web:x", 1)).rejects.toThrow();
    await down.close();
  });
});

describe("the seal store's privileges (infra/seal-store/schema.sql)", () => {
  beforeAll(async () => {
    await sealer.put({ log: "did:web:audit.locked.example", seq: 1, seal: "locked" });
  });

  it.each([
    ["update a copy", "UPDATE audit_seal_copies SET seal = 'x'"],
    ["delete a copy", "DELETE FROM audit_seal_copies"],
    ["truncate the table", "TRUNCATE audit_seal_copies"],
    ["drop the table", "DROP TABLE audit_seal_copies"],
    ["disable its triggers", "ALTER TABLE audit_seal_copies DISABLE TRIGGER ALL"],
  ])("the audit service's role cannot %s", async (_name, statement) => {
    expect(await attempt(database.sealerUrl, statement)).not.toBe("ok");
  });

  it("the auditor's role can read but not add", async () => {
    expect(await attempt(database.auditorUrl, "SELECT * FROM audit_seal_copies")).toBe("ok");
    expect(
      await attempt(
        database.auditorUrl,
        "INSERT INTO audit_seal_copies (log, seq, seal) VALUES ('did:web:x', 1, 'forged')",
      ),
    ).not.toBe("ok");
  });

  it.each([
    ["UPDATE audit_seal_copies SET seal = 'x'", "UPDATE"],
    ["DELETE FROM audit_seal_copies", "DELETE"],
    ["TRUNCATE audit_seal_copies", "TRUNCATE"],
  ])("even the owner is refused by the trigger, loudly: %s", async (statement, operation) => {
    expect(await attempt(database.url, statement)).toBe(
      `audit seal copies are append-only (${operation})`,
    );
  });

  it("still holds every copy afterwards", async () => {
    expect(await auditor.list("did:web:audit.locked.example", 1)).toEqual(["locked"]);
  });
});

import { createServer, type Server, type Socket } from "node:net";
import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { createDatabaseIndexReader } from "./database.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const pool = new pg.Pool({ connectionString: databaseUrl, max: 1 });
const inserted: string[] = [];
// Far above anything a serial allocates in a test run, so these never collide with real agents.
const BASE = 700_000_000;

beforeAll(async () => {
  await pool.query("DELETE FROM external_revoked_indexes WHERE status_list_index >= $1", [BASE]);
});
afterEach(async () => {
  await pool.query("DELETE FROM external_revoked_indexes WHERE status_list_index >= $1", [BASE]);
  for (const agentId of inserted.splice(0)) {
    await pool.query("DELETE FROM status_list_entries WHERE agent_id = $1", [agentId]);
  }
});
afterAll(async () => {
  await pool.end();
});

async function revokedAgent(index: number, revoked: boolean): Promise<void> {
  const agentId = randomUUID();
  inserted.push(agentId);
  await pool.query(
    "INSERT INTO status_list_entries (agent_did, agent_id, status_list_index, revoked_at) VALUES ($1, $2, $3, $4)",
    [`did:web:a.example:agents:${agentId}`, agentId, index, revoked ? new Date() : null],
  );
}

describe("createDatabaseIndexReader", () => {
  it("reads the indexes of revoked agents and of externally merged bits, and not of active agents", async () => {
    await revokedAgent(BASE + 1, true);
    await revokedAgent(BASE + 2, false);
    await pool.query(
      "INSERT INTO external_revoked_indexes (status_list_index, first_seen_in_list_at) VALUES ($1, now())",
      [BASE + 3],
    );
    const reader = createDatabaseIndexReader(databaseUrl, { timeoutMs: 5_000 });
    try {
      const indexes = (await reader.read()).filter((index) => index >= BASE);
      expect(indexes.sort()).toEqual([BASE + 1, BASE + 3]);
    } finally {
      await reader.close();
    }
  });

  it("fails promptly, instead of hanging, when nothing is listening", async () => {
    const reader = createDatabaseIndexReader("postgres://custos:custos@127.0.0.1:1/custos", {
      timeoutMs: 300,
    });
    const started = Date.now();
    try {
      await expect(reader.read()).rejects.toThrow();
      expect(Date.now() - started).toBeLessThan(3_000);
    } finally {
      await reader.close();
    }
  });

  describe("when the database accepts a connection and then never answers", () => {
    let server: Server;
    let port: number;
    const sockets: Socket[] = [];
    beforeAll(async () => {
      server = createServer((socket) => void sockets.push(socket)); // accept, say nothing
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("no port");
      port = address.port;
    });
    afterAll(async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it("is cut off after the timeout: a switched-off database host must not stall the publisher", async () => {
      const reader = createDatabaseIndexReader(
        `postgres://custos:custos@127.0.0.1:${port}/custos`,
        { timeoutMs: 300 },
      );
      const started = Date.now();
      try {
        await expect(reader.read()).rejects.toThrow();
        expect(Date.now() - started).toBeLessThan(3_000);
      } finally {
        await reader.close();
      }
    });
  });

  it("refuses a timeout that is not a positive whole number of milliseconds", () => {
    for (const timeoutMs of [0, -1, 1.5, Number.NaN]) {
      expect(() => createDatabaseIndexReader(databaseUrl, { timeoutMs })).toThrow("timeoutMs");
    }
  });
});

#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface, type Interface } from "node:readline";
import { fileURLToPath } from "node:url";
import { createApiKeyStore } from "@custos/control-plane-auth";
import { drizzle } from "drizzle-orm/node-postgres";
import { runAdminCli } from "./admin.js";
import { createDatabaseIndexReader } from "./publisher/database.js";
import { startDemo, type DemoDeps } from "./demo.js";
import { startFederationDemo } from "./federation-demo/demo.js";
import { runFederationStory } from "./federation-demo/story.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = drizzle(databaseUrl);
const store = createApiKeyStore(db);
const clock = { now: () => new Date() };
const out = (line: string): void => void process.stdout.write(`${line}\n`);

/** What both demos need from the outside world: processes, ports, the database. */
function processDeps(): DemoDeps {
  return {
    store,
    clock,
    out,
    spawn: (script, { cwd, env }) => {
      const child = spawn(process.execPath, [script], { cwd, env, stdio: "inherit" });
      return {
        onExit: (callback) => void child.on("exit", callback),
        kill: () => void child.kill(),
      };
    },
    fetch,
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    isPortFree: (port) =>
      new Promise((resolve) => {
        const probe = createServer();
        probe.once("error", () => resolve(false));
        probe.listen(port, "0.0.0.0", () => probe.close(() => resolve(true)));
      }),
    randomHex: (bytes) => randomBytes(bytes).toString("hex"),
    baseEnv: process.env,
    databaseUrl,
    // apps/admin/dist/bin.js → the repository root.
    repoRoot: fileURLToPath(new URL("../../..", import.meta.url))
      .replace(/\\/g, "/")
      .replace(/\/$/, ""),
  };
}

async function demo(): Promise<void> {
  const handle = await startDemo(processDeps());
  const shutdown = (): void => void handle.stop();
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  process.once("exit", handle.kill);
  await handle.finished;
}

/**
 * The federation demo moves on when the presenter presses Enter. While
 * readline owns the terminal, Ctrl-C reaches readline, not the process, so it
 * is forwarded to the same stop path. The prompt is created at the first
 * question, so Ctrl-C during startup behaves as it does for `demo`.
 */
async function demoFederation(): Promise<void> {
  let prompt: Interface | undefined;
  let stopDemo: () => void = () => {};
  const ask = (text: string): Promise<void> =>
    new Promise((resolve) => {
      if (prompt === undefined) {
        prompt = createInterface({ input: process.stdin, output: process.stdout });
        prompt.on("SIGINT", () => stopDemo());
      }
      prompt.question(
        `
${text} `,
        () => resolve(),
      );
    });
  try {
    const handle = await startFederationDemo({
      ...processDeps(),
      waitForStep: ask,
      makeWorkDir: () => mkdtemp(join(tmpdir(), "custos-federation-demo-")),
      cleanupWorkDir: (dir) => rm(dir, { recursive: true, force: true }),
      runStory: runFederationStory,
    });
    stopDemo = () => void handle.stop();
    process.once("SIGINT", stopDemo);
    process.once("SIGTERM", stopDemo);
    process.once("exit", handle.kill);
    out(`demo ended: ${await handle.finished}`);
  } finally {
    prompt?.close();
  }
}

/** A's revoked agents, read from its database with timeouts; one input to the publisher's union. */
const databaseReader = createDatabaseIndexReader(databaseUrl, { timeoutMs: 5_000 });

// `publish-status run` stops cleanly on Ctrl-C or a termination signal.
const stop = new AbortController();
process.once("SIGINT", () => stop.abort());
process.once("SIGTERM", () => stop.abort());

try {
  await runAdminCli(process.argv, {
    store,
    clock,
    out,
    demo,
    demoFederation,
    publisher: {
      env: process.env,
      clock,
      out,
      readDatabaseIndexes: databaseReader.read,
      signal: stop.signal,
    },
  });
} finally {
  await databaseReader.close();
  await db.$client.end();
}

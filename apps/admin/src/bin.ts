#!/usr/bin/env node
import { createApiKeyStore } from "@custos/control-plane-auth";
import { drizzle } from "drizzle-orm/node-postgres";
import { runAdminCli } from "./admin.js";

const db = drizzle(process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos");
try {
  await runAdminCli(process.argv, {
    store: createApiKeyStore(db),
    clock: { now: () => new Date() },
    out: (line) => process.stdout.write(`${line}\n`),
  });
} finally {
  await db.$client.end();
}

// One agent's full lifecycle through @custos/sdk, against the local stack.
// Run from the repo root: node packages/sdk/examples/quickstart.mjs
// Prerequisites (see README): services running, `pnpm build`, a
// `mock-database` secret stored in the vault, and CUSTOS_OPERATOR_KEY set.
import { performance } from "node:perf_hooks";
import { createCustos } from "@custos/sdk";

const custos = createCustos({
  identityUrl: "http://localhost:4001",
  vaultUrl: "http://localhost:4002",
  revocationUrl: "http://localhost:4003",
  // register, grant and deprovision are operator actions (ADR 0008).
  operatorKey: process.env.CUSTOS_OPERATOR_KEY,
});

const agent = await custos.register();
console.log(`registered ${agent.did}`);

const database = custos.connect(agent, "mock-database");

const beforeGrant = await database.call("query", { table: "customers" });
console.log(`before grant: ${beforeGrant.ok ? "allowed" : `denied (${beforeGrant.error.code})`}`);

await custos.grant(agent, "mock-database");
const allowed = await database.call("query", { table: "customers" });
console.log(
  `after grant:  ${allowed.ok ? `allowed → ${JSON.stringify(allowed.value)}` : `denied (${allowed.error.code})`}`,
);

const started = performance.now();
await custos.deprovision(agent, { reason: "quickstart" });
const afterRevoke = await database.call("query", { table: "customers" });
const elapsed = Math.round(performance.now() - started);
console.log(
  `after deprovision: ${afterRevoke.ok ? "allowed (unexpected!)" : `denied (${afterRevoke.error.code})`} — ${elapsed} ms from revoke to refusal`,
);

if (beforeGrant.ok || !allowed.ok || afterRevoke.ok) process.exitCode = 1;

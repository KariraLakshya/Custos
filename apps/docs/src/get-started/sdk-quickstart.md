# SDK quickstart

`@custos/sdk` does from TypeScript or JavaScript what the CLI does from a terminal. This page runs one agent's whole life in about thirty lines.

::: info Not on npm yet
`@custos/sdk` is a private workspace package. Run code that uses it from inside the Custos repository.
:::

## Before you start

- `pnpm demo` is running ([Install and run](/get-started/installation)). It builds the SDK and stores `mock-database` in the vault.
- `CUSTOS_OPERATOR_KEY` is set in your terminal to the operator key `pnpm demo` printed.

## Run the example

The repository ships the flow below as `packages/sdk/examples/quickstart.mjs`. From the repository root:

```bash
node packages/sdk/examples/quickstart.mjs
```

```text
registered did:web:localhost%3A4001:agents:…
before grant: denied (POLICY_DENIED)
after grant:  allowed → [{"id":1,"name":"Ada Lovelace"},{"id":2,"name":"Alan Turing"}]
after deprovision: denied (AGENT_REVOKED) — 24 ms from revoke to refusal
```

The last number is measured on your machine each run.

## The code

```ts
import { createCustos } from "@custos/sdk";

const custos = createCustos({
  identityUrl: "http://localhost:4001",
  vaultUrl: "http://localhost:4002",
  revocationUrl: "http://localhost:4003",
  // register, grant and deprovision are operator actions.
  operatorKey: process.env.CUSTOS_OPERATOR_KEY,
});

// Generates the agent's key pair here, proves it holds the private key,
// and returns { id, did, name, credential, secretKey }.
const agent = await custos.register();

const database = custos.connect(agent, "mock-database");

const before = await database.call("query", { table: "customers" });
// before.ok === false, before.error.code === "POLICY_DENIED"

await custos.grant(agent, "mock-database");
const allowed = await database.call("query", { table: "customers" });
if (allowed.ok) console.log(allowed.value);

await custos.deprovision(agent, { reason: "quickstart" });
const after = await database.call("query", { table: "customers" });
// after.ok === false, after.error.code === "AGENT_REVOKED"
```

## Three things to notice

**The agent's private key never leaves your process.** `register()` returns it as `agent.secretKey` (64 hex characters). Store it like any private key; Custos never receives it. `agent` is plain JSON, so you can save it and hand it to the agent's own process.

**An agent process needs no operator key.** `connect(...).call(...)` doesn't use one. Give the operator key only to the process that registers, grants and revokes, so a compromised agent cannot grant itself tools:

```ts
// In the agent's own process:
const custos = createCustos({ identityUrl, vaultUrl, revocationUrl }); // no operatorKey
const result = await custos.connect(agent, "mock-database").call("query", { table: "customers" });
```

**A refusal is a value, not an exception.** `call()` returns `{ ok: true, value }` or `{ ok: false, error }`, where `error` has the vault's `code` (such as `POLICY_DENIED`), the HTTP `status`, and the `stage` that refused (`token` or `call`). So a denial can't be mistaken for a network failure and retried. `call()` throws only when a service can't be reached or sends a response it can't validate. The operator actions (`register`, `grant`, `deprovision`) throw a `CustosError` with the service's `code`.

## Next

- Every function and type: [SDK reference](/reference/sdk).
- Passing work to another agent from code: `custos.delegate(...)` in the [SDK reference](/reference/sdk#delegate).

# Custos

A trust layer for AI agents. Every agent gets a cryptographic identity, never holds a real tool password, can only use the tools it has been granted, can be cut off from every tool in well under a second, and leaves a signed, independently verifiable record of everything it did.

MCP and A2A define how agents talk. Custos decides whether an agent should be trusted and what it may do. It runs on top of those protocols rather than replacing them.

**Status:** the MVP runs end to end locally: identity, vault, revocation, allowlists, audit, CLI, SDK, and a live dashboard. It is a development build. Signing keys are in memory (a KMS-backed key provider is planned), and nothing here is hardened for production. See [docs/build-plan.md](./docs/build-plan.md).

---

## Quickstart: zero to a revoked agent

About 10 minutes. By the end you will have registered an agent, watched it be refused, granted it one tool, used that tool without ever seeing its password, cut it off, and verified the signed audit trail of all of it.

### What you need

- **Node 22** or later
- **pnpm 9**: `npm install -g pnpm@9.15.0`
- **Docker Desktop**, running. It doesn't start by itself; open it first.
- **A shell:** bash/zsh (macOS, Linux, Git Bash) or **PowerShell 7+** on Windows. Windows PowerShell 5.1 mangles the JSON arguments used below.

Every command runs from the repository root.

### 1. Install, start the databases, build

```bash
git clone https://github.com/KariraLakshya/Custos.git
cd Custos
pnpm install
pnpm dev        # Postgres (port 5433) and Redis (6379) in Docker
pnpm migrate    # create the database tables
pnpm build
```

`pnpm dev` starts only the databases. The Custos services come next.

### 2. Start the services

Custos is four small services plus a dashboard. Open **five terminals** at the repo root and start one in each, **in this order**. Revocation must be up before identity and vault, because both contact it.

| #   | Command                                  | Port | What it does                                                    |
| --- | ---------------------------------------- | ---- | --------------------------------------------------------------- |
| 1   | `pnpm --filter @custos/audit start`      | 4004 | Stores and signs the audit trail                                |
| 2   | `pnpm --filter @custos/revocation start` | 4003 | Tracks which agents are revoked; pushes revocations out         |
| 3   | `pnpm --filter @custos/identity start`   | 4001 | Registers agents and issues their identity credentials          |
| 4   | vault, see below                         | 4002 | Holds the real tool passwords and makes calls on agents' behalf |
| 5   | `pnpm --filter @custos/dashboard start`  | 4005 | Live view of every decision                                     |

The vault encrypts stored tool passwords with a key you provide, and refuses to start without one:

```bash
# bash / zsh
export VAULT_MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
pnpm --filter @custos/vault start
```

```powershell
# PowerShell
$env:VAULT_MASTER_KEY = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
pnpm --filter @custos/vault start
```

Keep this key for as long as you want the stored passwords to stay readable. A vault restarted with a different key can't decrypt them, so re-store them (step 3).

Now open **http://localhost:4005** and keep it visible. Every allow and deny below appears there live.

### 3. Give the vault the tool passwords

The vault holds the real credentials for each tool. Agents never see them. This walkthrough uses two built-in stand-in tools that accept any secret:

```bash
pnpm --filter @custos/vault seed mock-database any-placeholder-secret
pnpm --filter @custos/vault seed mock-slack any-placeholder-secret
```

| Tool            | Action           | Input                                                                                     |
| --------------- | ---------------- | ----------------------------------------------------------------------------------------- |
| `mock-database` | `query`          | `{"table":"customers"}`                                                                   |
| `mock-slack`    | `post-message`   | `{"channel":"#ops","text":"hi"}`                                                          |
| `stripe`        | `list-customers` | `{}`. Needs a real Stripe **test-mode** key (`sk_test_…`) seeded instead of a placeholder |

### 4. Walk through an agent's life with the CLI

Make `custos` a shortcut for this terminal:

```bash
alias custos="node apps/cli/dist/bin.js"                  # bash / zsh
```

```powershell
function custos { node apps/cli/dist/bin.js @args }      # PowerShell
```

**Register an agent.** This creates its keypair, publishes its identity document, and issues its signed identity credential:

```bash
custos register --out agent.json
```

Note the `"id"` near the top of the output; you'll need it to revoke the agent. `agent.json` is the agent's credential. Whoever holds it can act as that agent, so treat it like a password. It's already gitignored.

**Check the credential independently.** This fetches the agent's public identity document fresh and verifies the signature itself rather than trusting the server's word:

```bash
custos verify agent.json
# verified: credential is authentic
```

**Try to use a tool. It's refused.** Custos denies by default: being registered doesn't mean being allowed.

```bash
custos use mock-database query --credential agent.json --input '{"table":"customers"}'
# denied: POLICY_DENIED
```

**Grant exactly one tool, then try again:**

```bash
custos grant mock-database --credential agent.json
custos use mock-database query --credential agent.json --input '{"table":"customers"}'
# { "result": [ { "id": 1, "name": "Ada Lovelace" }, { "id": 2, "name": "Alan Turing" } ] }
```

Behind that one command, the agent showed its credential to the vault and got a pass valid for 60 seconds and for this one tool and action. The vault then made the call using the real password. The agent never saw it.

**The grant covers only that tool.** Slack is still refused:

```bash
custos use mock-slack post-message --credential agent.json --input '{"channel":"#ops","text":"hi"}'
# denied: POLICY_DENIED
```

**Revoke the agent.** Use the `id` from registration:

```bash
custos deprovision <id> --reason "compromised"
```

`"broadcast": { "delivered": 1 }` in the output means the signed revocation notice was pushed straight to the vault; nobody has to wait for it to check. The dashboard shows the agent as cut off.

**Try again. It's refused everywhere:**

```bash
custos use mock-database query --credential agent.json --input '{"table":"customers"}'
# denied: AGENT_REVOKED
```

**Pull the audit trail.** Every attempt above, allowed or refused, was recorded and signed. The CLI checks each record's signature against the audit service's published key and exits non-zero if any fails:

```bash
custos audit-log
```

Pass an agent's DID (the `"did"` from registration) to see just that agent: `custos audit-log <did>`.

### 5. Do the same from code with the SDK

```ts
import { createCustos } from "@custos/sdk";

const custos = createCustos({
  identityUrl: "http://localhost:4001",
  vaultUrl: "http://localhost:4002",
  revocationUrl: "http://localhost:4003",
});

const agent = await custos.register(); // plain JSON: { id, did, credential }
await custos.grant(agent, "mock-database");

const database = custos.connect(agent, "mock-database");
const result = await database.call("query", { table: "customers" });
if (result.ok) console.log(result.value);
else console.log(`denied: ${result.error.code}`); // POLICY_DENIED, AGENT_REVOKED, INVALID_TOKEN, …

await custos.deprovision(agent, { reason: "compromised" });
```

A refused call **returns** `{ ok: false, error }` rather than throwing, so a denial can't be mistaken for a network hiccup and retried. The SDK throws only when a service is unreachable or sends a response it can't validate.

That exact flow is runnable (with the services from step 2 running and `mock-database` seeded in step 3):

```bash
node packages/sdk/examples/quickstart.mjs
# registered did:web:localhost%3A4001:agents:…
# before grant: denied (POLICY_DENIED)
# after grant:  allowed → [{"id":1,"name":"Ada Lovelace"},{"id":2,"name":"Alan Turing"}]
# after deprovision: denied (AGENT_REVOKED) — 24 ms from revoke to refusal
```

`@custos/sdk` isn't published to npm yet, so run code that uses it from inside this repository.

### Stopping

Stop each service with Ctrl+C, then `pnpm dev:down` to stop the databases. Data persists in a Docker volume between runs.

---

## Troubleshooting

| Symptom                                                                   | Cause and fix                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pnpm dev` fails with `failed to connect to the docker API`               | Docker Desktop isn't running. Start it and wait until it's ready.                                                                                                                                                                                |
| Vault exits with `VAULT_MASTER_KEY … must be 64 hex characters`           | Set the key in the **same terminal** before starting the vault (step 2).                                                                                                                                                                         |
| `custos register` fails with a 502                                        | The revocation service isn't running. Identity needs it to reserve the agent's revocation slot, and refuses to create an agent that couldn't be revoked.                                                                                         |
| Calls denied with `REVOCATION_STATE_STALE`                                | The vault can't reach the revocation service, so it refuses rather than risk allowing a revoked agent. Start revocation; the vault catches up within ~10 s.                                                                                      |
| `use` fails with a 404 `UNKNOWN_TOOL`                                     | The tool's password isn't in the vault (or the tool name is misspelled). Run the seed command in step 3.                                                                                                                                         |
| `use` fails with a 500 `invalid tag`                                      | The stored tool password was encrypted under a different `VAULT_MASTER_KEY`: the vault was restarted with a new key, or `pnpm test` / `pnpm test:e2e` ran against the same database and stored test secrets. Re-run the seed commands in step 3. |
| Windows: Docker can't bind port 5433 (`access permissions`, not "in use") | Windows NAT reserved the port. From an **elevated** shell: `net stop winnat`, `netsh int ipv4 add excludedportrange protocol=tcp startport=5433 numberofports=1 store=persistent`, `net start winnat`.                                           |
| Something else already uses 5432                                          | Expected. Custos's Postgres uses **5433** on purpose.                                                                                                                                                                                            |

---

## Development

```bash
pnpm test        # unit + integration (databases from `pnpm dev` must be up, and migrated)
pnpm test:e2e    # full lifecycle across real services
pnpm lint
pnpm typecheck
```

The test suite includes negative cases for every security control: a tampered credential, an expired token, a revoked agent, an unknown signing key, and a tool outside the allowlist are each proven to fail.

## Repository layout

- `apps/`: `cli` (the `custos` command) and `dashboard`
- `packages/`: `core` (crypto, DIDs, credentials; pure, no I/O), `sdk`, `contracts`, `connectors` (per-tool adapters), `config`, `observability`, `testing`
- `services/`: `identity`, `vault`, `revocation`, `audit`
- `infra/`: Docker Compose and database migrations
- `docs/`: build plan, architecture decision records (`docs/adr/`), progress log

Engineering standards and architecture rules: [CLAUDE.md](./CLAUDE.md). Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md). Security issues: [SECURITY.md](./SECURITY.md).

# Custos

**An early-stage, open-source developer platform for AI agents, building toward a hosted trust service.** [custoss.dev](https://custoss.dev)

Custos is the trust layer for AI agents. Developers give every agent a cryptographic identity, keep real tool passwords out of agents entirely, allow each agent only the tools it has been granted, cut a compromised agent off from every tool in well under a second, and get a signed, independently verifiable record of everything it did.

MCP and A2A define how agents talk. Custos decides whether an agent should be trusted and what it may do. It runs on top of those protocols rather than replacing them.

**What you get today:** a TypeScript SDK and a `custos` CLI, backed by four services (identity, vault, revocation, audit) that you run yourself with Docker Compose, plus a live dashboard.

**Where it's going:** a hosted Custos, where a developer connects their agents and tools and Custos runs identity, credential custody, revocation and audit as a managed cloud service. The services here are the core of that offering, and they're being hardened toward it.

**Status:** early stage. The MVP runs end to end locally: identity, vault, revocation, allowlists, audit, CLI, SDK, and the dashboard. It is a development build, not yet hosted. Cross-organisation federation (an organisation accepting another's agents, with the issuer switched off) is built and proven by an end-to-end test on one machine. The key that signs agent credentials can live in AWS KMS; the other services' signing keys are still in memory. Nothing here is hardened for production: [docs/threat-model.md](./docs/threat-model.md) lists what is and isn't protected. See [docs/build-plan.md](./docs/build-plan.md).

---

## Quickstart: zero to a revoked agent

About 10 minutes. By the end you will have registered an agent, watched it be refused, granted it one tool, used that tool without ever seeing its password, cut it off, and verified the signed audit trail of all of it.

### What you need

- **Node 22** or later
- **pnpm 9**: `npm install -g pnpm@9.15.0`
- **Docker Desktop**, running. It doesn't start by itself; open it first.
- **A shell:** bash/zsh (macOS, Linux, Git Bash) or **PowerShell 7+** on Windows. Windows PowerShell 5.1 mangles the JSON arguments used below.

Every command runs from the repository root.

### Quick start: one command

If you only want to see Custos working, install and start the databases, then let one command do the rest:

```bash
pnpm install
pnpm dev        # Postgres and Redis in Docker; wait a few seconds for Postgres
pnpm demo       # migrate, build, create keys, start all five services, store the stand-in tools
```

It prints the dashboard address and your operator key, then keeps running; press Ctrl-C to stop everything. Then follow **step 4** below in a second terminal, in an empty directory. All the keys it generates stay in memory and the database: nothing is written to disk, the API keys expire in 12 hours, and they are revoked when you stop it. Each run uses new keys, so credentials from an earlier run stop verifying.

The numbered steps below do the same thing by hand, one service per terminal. They are what the first-time-reader check (`docs/readme-test.md`) follows.

### 1. Install, start the databases, build

```bash
git clone https://github.com/KariraLakshya/Custos.git
cd Custos
pnpm install
pnpm dev        # Postgres (port 5433) and Redis (6379) in Docker
pnpm migrate    # create the database tables
pnpm build
```

`pnpm dev` starts only the databases.

Then create your local keys. Custos only accepts admin actions (registering, granting, revoking, storing tool passwords) from someone holding an **operator key**, and its services only accept each other's calls with a **service key**:

```bash
pnpm -s custos-admin dev-keys                       # bash / zsh
```

```powershell
pnpm -s custos-admin dev-keys --shell powershell    # PowerShell
```

It prints four lines, each ready to paste, and says which terminal each one goes in: `REVOCATION_SERVICE_KEY` for revocation, `IDENTITY_SERVICE_KEY` for identity, `VAULT_SERVICE_KEY` for the vault, and `CUSTOS_OPERATOR_KEY` for the terminal you'll run the `custos` commands in. Each key is shown **once**; Custos keeps only a fingerprint of it. Keep the output until step 4. This command talks to the database directly, which is deliberate: there is no web endpoint for creating keys. `pnpm custos-admin key list` shows your keys, and `pnpm custos-admin key revoke <id>` cancels one.

The Custos services come next.

### 2. Start the services

Custos is four small services plus a dashboard. Open **five terminals** at the repo root and start one in each, **in this order**. Revocation must be up before identity and vault, because both contact it.

| #   | Command                                 | Port | What it does                                                    |
| --- | --------------------------------------- | ---- | --------------------------------------------------------------- |
| 1   | audit, see below                        | 4004 | Keeps the audit trail as a sealed, tamper-evident ledger        |
| 2   | revocation, see below                   | 4003 | Tracks which agents are revoked; pushes revocations out         |
| 3   | identity, see below                     | 4001 | Registers agents and issues their identity credentials          |
| 4   | vault, see below                        | 4002 | Holds the real tool passwords and makes calls on agents' behalf |
| 5   | `pnpm --filter @custos/dashboard start` | 4005 | Live view of every decision                                     |

Revocation, identity and the vault each need their service key from step 1: they use it to write to the audit log, so every admin action is recorded with who did it. **Paste that service key line into the terminal first**, then start the service. A service started with a missing, revoked or wrongly scoped service key refuses to start.

The audit service seals its ledger with its own key, generated from a seed (ADR 0017). Keep the seed: a new seed is a new key, and `custos audit-log` will ask you to accept it once (see step 4). Seals are also copied to a separate seal server, started by `pnpm dev` on port 5434; point the audit service at it as its insert-only user:

```bash
export AUDIT_SEAL_STORE_URL=postgres://custos_sealer:custos_sealer@localhost:5434/custos_seals
```

```powershell
$env:AUDIT_SEAL_STORE_URL = "postgres://custos_sealer:custos_sealer@localhost:5434/custos_seals"
```

Reset the main database and the seal server **together** (`pnpm dev:down`, then remove both Docker volumes). A fresh audit log next to old seal copies starts again at entry 1, and its first copy clashes with the old one: copying stops and every check fails.

```bash
# bash / zsh: audit's terminal
export AUDIT_SIGNING_SEED=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
pnpm --filter @custos/audit start
```

```powershell
# PowerShell: audit's terminal
$env:AUDIT_SIGNING_SEED = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
pnpm --filter @custos/audit start
```

Revocation signs every revocation notice with its own key, generated from a seed. Keep the seed: restart revocation with the **same** seed and the vault keeps trusting it without re-checking every past revocation.

```bash
# bash / zsh: revocation's terminal, after pasting its REVOCATION_SERVICE_KEY line
export REVOCATION_SIGNING_SEED=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
pnpm --filter @custos/revocation start
```

```powershell
# PowerShell: revocation's terminal, after pasting its REVOCATION_SERVICE_KEY line
$env:REVOCATION_SIGNING_SEED = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
pnpm --filter @custos/revocation start
```

Identity and the vault also need a second secret of their own: a signing key and an encryption key.

The identity service signs every agent's credential with its **issuer key**, generated from this seed:

```bash
# bash / zsh
export IDENTITY_ISSUER_SEED=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
pnpm --filter @custos/identity start
```

```powershell
# PowerShell
$env:IDENTITY_ISSUER_SEED = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
pnpm --filter @custos/identity start
```

Save the seed. Restart identity with the **same** seed and every credential it issued stays valid; start it with a new one and they all stop verifying.

The vault encrypts stored tool passwords with its own key:

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

Both are local-development keys held in environment variables. Production uses AWS KMS, where the key can sign but can never be read out.

Now open **http://localhost:4005** and keep it visible. Every allow and deny below appears there live.

### 3. Give the vault the tool passwords

Use a new terminal for this step and step 4, and paste the `CUSTOS_OPERATOR_KEY` line from step 1 into it first: storing a password is an admin action.

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

Stay in the terminal from step 3: `register`, `grant` and `deprovision` read your operator key from `CUSTOS_OPERATOR_KEY`. (They read it only from the environment, never a command-line flag, so it stays out of your shell history.) Using a tool doesn't need it: an agent never holds an operator key.

Make `custos` a shortcut for this terminal:

```bash
alias custos="node apps/cli/dist/bin.js"                  # bash / zsh
```

```powershell
function custos { node apps/cli/dist/bin.js @args }      # PowerShell
```

**Register an agent.** The CLI generates the agent's keypair **on your machine**, proves to the identity service that it holds the private key, and gets back a credential the identity service signs, naming the agent and its public key:

```bash
custos register --out agent.json
```

This writes two files:

- **`agent.key`**: the agent's private key. It never leaves your machine; it isn't sent to Custos and isn't printed. `register` won't overwrite an existing key file.
- **`agent.json`**: the agent's credential.

Note the `"id"` near the top of the output; you'll need it to revoke the agent. Keep `agent.key` private and don't share it; it's gitignored. `agent.json` on its own is useless to anyone who copies it: every access request must be signed with `agent.key`, so without the key the vault refuses (`denied: INVALID_PROOF_OF_POSSESSION`).

**Check the credential independently.** This fetches the identity service's public identity document fresh and verifies the credential's signature itself, rather than trusting the server's word:

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

Behind that one command, the agent showed its credential to the vault, **signed the request with `agent.key`** to prove the credential is its own, and got a pass valid for 60 seconds and for this one tool and action. The vault then made the call using the real password. The agent never saw it. (`use` reads `agent.key` by default; pass `--key <path>` for another agent.)

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

**Pull the audit trail.** Every attempt above, allowed or refused, was recorded. The audit log is a ledger: each entry is linked to the one before it, and every 10 seconds the newest entry is sealed with the audit service's key (ADR 0017). The CLI checks the whole chain against that seal, and against the newest seal it remembered from its last check (in `~/.custos/audit-seal.json`), and exits non-zero if anything was edited, removed or rewritten:

```bash
custos audit-log
```

Your own admin actions are in it too: registering the agent, granting the tool, storing the passwords and revoking the agent each appear with a `principal` naming the key that did it (`dev-operator`), alongside the agent's own actions.

Pass an agent's DID (the `"did"` from registration) to see just that agent: `custos audit-log <did>`. Entries from the last few seconds show as `unsealedCount` until the next seal. Each entry also names the service that reported it (`reportedBy`).

To also check the copies on the separate seal server, which someone who changes the audit database can't delete, give the CLI its read-only user. It is read from the environment only, because it contains a password:

```bash
export CUSTOS_AUDIT_SEAL_STORE_URL=postgres://custos_auditor:custos_auditor@localhost:5434/custos_seals
```

```powershell
$env:CUSTOS_AUDIT_SEAL_STORE_URL = "postgres://custos_auditor:custos_auditor@localhost:5434/custos_seals"
```

Without it, `audit-log` says `"outsideSealsChecked": false` and prints a note.

In production, the copies go to an AWS S3 bucket with Object Lock instead, which nobody can delete from during its retention period, not even the bucket's own administrator: set both variables to `s3://<bucket>`. The bucket needs Object Lock with a default COMPLIANCE retention, or the audit service refuses to start. The IAM policies for the audit service and for auditors are in `infra/seal-store/aws/`.

**After a restart with a new audit key** (every `pnpm demo` run, unless `AUDIT_SIGNING_SEED` stays set), `audit-log` stops with `KEY_CHANGED` and shows the new key. Check it against the `audit seal key` line `pnpm demo` printed (never against the audit service's own `/.well-known/did.json`, which the service controls), then accept it once:

```bash
custos audit-log --accept-key <the key it showed>
```

The keys you have accepted are kept in `~/.custos/audit-seal.json`, and seals made under each are still checked.

### 5. Do the same from code with the SDK

```ts
import { createCustos } from "@custos/sdk";

const custos = createCustos({
  identityUrl: "http://localhost:4001",
  vaultUrl: "http://localhost:4002",
  revocationUrl: "http://localhost:4003",
  operatorKey: process.env.CUSTOS_OPERATOR_KEY, // for register, grant, deprovision
});

const agent = await custos.register(); // plain JSON: { id, did, credential }
await custos.grant(agent, "mock-database");

const database = custos.connect(agent, "mock-database");
const result = await database.call("query", { table: "customers" });
if (result.ok) console.log(result.value);
else console.log(`denied: ${result.error.code}`); // POLICY_DENIED, AGENT_REVOKED, INVALID_TOKEN, …

await custos.deprovision(agent, { reason: "compromised" });
```

An agent's own process passes no `operatorKey`: `connect(...).call(...)` doesn't need one, so a compromised agent can't grant itself tools.

A refused call **returns** `{ ok: false, error }` rather than throwing, so a denial can't be mistaken for a network hiccup and retried. The SDK throws only when a service is unreachable or sends a response it can't validate.

That exact flow is runnable (with the services from step 2 running, `mock-database` seeded in step 3, and `CUSTOS_OPERATOR_KEY` set):

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

### Optional: services authenticate to each other with certificates (mTLS)

Instead of service keys, Custos's services can prove who they are to each other with certificates, through an Envoy proxy (ADR 0009). Operators still use their operator key.

```bash
pnpm dev:mtls     # makes a dev certificate authority and certificates, then starts Envoy (Docker)
```

On Linux, run `export CUSTOS_ENVOY_USER=$(id -u):$(id -g)` first, so Envoy can read the keys the generator gave you. Then start each service with its certificate **instead of** its `*_SERVICE_KEY`, with `C=infra/mtls/certs` and `MTLS_CA=$C/ca.crt` set in every terminal:

| Service    | Settings (in addition to its usual ones)                                                                                                                                                                                                           |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| audit      | `AUDIT_MTLS_PORT=4014 AUDIT_MTLS_SERVER_CERT=$C/audit-server.crt AUDIT_MTLS_SERVER_KEY=$C/audit-server.key`                                                                                                                                        |
| revocation | `AUDIT_URL=https://localhost:5004 REVOCATION_MTLS_CERT=$C/revocation.crt REVOCATION_MTLS_KEY=$C/revocation.key REVOCATION_MTLS_PORT=4013 REVOCATION_MTLS_SERVER_CERT=$C/revocation-server.crt REVOCATION_MTLS_SERVER_KEY=$C/revocation-server.key` |
| identity   | `REVOCATION_URL=https://localhost:5003 AUDIT_URL=https://localhost:5004 IDENTITY_MTLS_CERT=$C/identity.crt IDENTITY_MTLS_KEY=$C/identity.key`                                                                                                      |
| vault      | `AUDIT_URL=https://localhost:5004 VAULT_MTLS_CERT=$C/vault.crt VAULT_MTLS_KEY=$C/vault.key`                                                                                                                                                        |

A service refuses to start if its certificate is for another service, has expired, or if it's given both a key and a certificate. The audit log then names each service by its certificate (`spiffe://custos.local/service/…`). The certificates and keys live in `infra/mtls/certs/`, which is gitignored.

### Optional: administrators sign in with a company account (SSO)

Instead of handing out operator keys, administrators can sign in with their company login, through any OpenID Connect provider (ADR 0010). Locally, Keycloak stands in for the company:

```bash
pnpm dev:sso      # starts Keycloak on http://localhost:8180 (Docker) with a demo realm
```

Start identity with these settings, as well as its usual ones:

```bash
SSO_ISSUER=http://localhost:8180/realms/custos
SSO_ALLOW_HTTP_ISSUER=true                     # plain http is accepted only for localhost
SSO_CLIENT_ID=custos-identity
SSO_CLIENT_SECRET=custos-dev-sso-client-secret-not-for-production
SSO_REDIRECT_URL=http://localhost:4001/operator/callback
SSO_GROUP_SCOPES='{"custos-admins":["agents:register","agents:revoke","credentials:write","policies:write"]}'
```

Then, in your own terminal:

```bash
custos login      # opens the sign-in page; demo user alice / alice-dev-password
```

`custos login` saves a key that lasts 8 hours (`SSO_SESSION_HOURS`) to `~/.custos/operator.key`, owner-only, and never prints it. `register`, `grant` and `deprovision` use it whenever `CUSTOS_OPERATOR_KEY` isn't set. Only people in a group listed in `SSO_GROUP_SCOPES` can sign in: the demo user `bob` is in none, so he's refused. Everything they do appears in the audit log under their email. The demo realm's passwords and client secret are for local use only.

### Optional: trust another organisation's agents (federation)

Organisation B can accept agents that organisation A issued without ever calling A, even while A is switched off (ADR 0014). Three pieces:

- **A's publisher.** `custos-admin publish-status` runs on A's security operator's machine. It signs A's list of revoked agents and writes it to a file that any static host serves (a bucket, a CDN). Revoking works with all of A's services off. The seed is A's revocation signing seed, from the environment only:

  ```bash
  CUSTOS_PUBLISHER_SIGNING_SEED=<A's REVOCATION_SIGNING_SEED> pnpm -s custos-admin publish-status revoke \
    --domain <A's revocation domain> --dir ./publisher --out ./site/status.json --validity-seconds 3600 \
    --credential agent.json --identity-did <A's identity DID> --identity-public-key <its key, from /.well-known/did.json> \
    --operator <your name> --reason <why>
  ```

  The first publish needs `publish-status init` with the same `--domain`, `--dir`, `--out` and `--validity-seconds`; `pnpm -s custos-admin publish-status --help` lists every option. The signing key is a development seed for now and must move to KMS before real use.

- **B's trust anchor.** B writes down A's two public keys and the list's address once, out of band (`parseTrustAnchors` in `@custos/federation`).
- **B's gate.** `createStatusCache` keeps a verified copy of A's list, fetched only from the configured address, and `createForeignAgentGate` checks each call: A's signature on the credential, the caller's proof that it holds the agent's key and that the proof was made for this very tool and action (pass them from your own routing, never from the caller; ADR 0015), and A's list. The answer is allowed, `401 UNAUTHORIZED` (the same for every bad credential or proof), `403 AGENT_REVOKED`, or `503 UNAVAILABLE` when B cannot confirm a recent list. A 503 still refuses. Allows and refusals of genuine agents are written to B's own audit log.

To watch it live, with the dashboard:

```bash
pnpm demo:federation
```

It starts A's identity and revocation services, B's audit service and the dashboard (ports 4001, 4003, 4004, 4005, plus 4006 for the list's file host), registers two agents at A and has them call B every few seconds. Open http://localhost:4005: the "Across organisations" panel shows B's decisions. Press Enter to switch A off (the agents keep working), Enter again to fire agent 1 through A's publisher (B refuses it, with a toast, while agent 2 carries on), and Enter or Ctrl-C to stop. In this demo A's database stays up, because B's audit service shares it; the test below switches it off too.

To see the whole story run as a test (two databases, A's real identity and revocation services, a static host, B's audit service):

```bash
pnpm --filter @custos/admin test:e2e
```

It registers two agents at A, has B accept them, stops A's services and makes A's database refuse connections, and has B accept them again. It then revokes one through the publisher (B refuses it within one poll), takes the host away until the list goes stale (B refuses both), and publishes again (B lets the other back in). Both organisations share one Postgres server and one machine in this run. B has no HTTP endpoint of its own yet: an application embeds the gate.

## Troubleshooting

| Symptom                                                                                      | Cause and fix                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm demo` or `pnpm migrate` fails with `ECONNREFUSED … 5433`                               | Postgres isn't ready yet. Wait a few seconds after `pnpm dev` and try again; check Docker Desktop is running.                                                                                                                                                                                                                                  |
| `pnpm demo` says ports are already in use                                                    | An earlier demo or manual run is still holding them. Stop it. If it was killed rather than stopped with Ctrl-C, find the leftovers: `Get-NetTCPConnection -LocalPort 4001,4002,4003,4004,4005 -State Listen` (PowerShell) and stop those `node` processes.                                                                                     |
| `pnpm dev` fails with `failed to connect to the docker API`                                  | Docker Desktop isn't running. Start it and wait until it's ready.                                                                                                                                                                                                                                                                              |
| Revocation exits with `REVOCATION_SIGNING_SEED … expected string`                            | Set the seed in the **same terminal** before starting revocation (step 2). Reuse the original seed on restarts.                                                                                                                                                                                                                                |
| Identity exits with `IDENTITY_ISSUER_SEED … expected string`                                 | Set the seed in the **same terminal** before starting identity (step 2).                                                                                                                                                                                                                                                                       |
| Vault exits with `VAULT_MASTER_KEY … must be 64 hex characters`                              | Set the key in the **same terminal** before starting the vault (step 2).                                                                                                                                                                                                                                                                       |
| A service exits with `REVOCATION_SERVICE_KEY`, `IDENTITY_SERVICE_KEY` or `VAULT_SERVICE_KEY` | The service key is missing, mistyped, revoked or expired, or it's another service's key. Paste the right line from `pnpm -s custos-admin dev-keys` into that terminal, or run it again for a fresh set.                                                                                                                                        |
| `set CUSTOS_OPERATOR_KEY to an operator key`                                                 | Paste the `CUSTOS_OPERATOR_KEY` line from `dev-keys` into this terminal.                                                                                                                                                                                                                                                                       |
| A command fails with `401` and `UNAUTHORIZED`                                                | The operator key was refused: mistyped, revoked, expired, or from another database. Every reason gives the same answer on purpose. Check `pnpm custos-admin key list`; after 10 failures in 5 minutes your address is also locked out for 15 minutes.                                                                                          |
| `custos register` fails with `refusing to overwrite existing key file`                       | An `agent.key` from an earlier registration is in the way. Move it, or pass `--key-out <path>` for the new agent.                                                                                                                                                                                                                              |
| Every call denied with `INVALID_AGENT_CREDENTIAL` after restarting identity                  | Identity was restarted with a **different** `IDENTITY_ISSUER_SEED`, so earlier credentials no longer verify. Restart it with the original seed, or register agents again.                                                                                                                                                                      |
| `use` denied with `INVALID_PROOF_OF_POSSESSION`                                              | Either the key doesn't match the credential (the wrong `agent.key` for this `agent.json`), or the vault's `VAULT_PUBLIC_URL` isn't the address you're calling. Requests are signed for the exact URL used, so `localhost` and `127.0.0.1` count as different. Use `--vault-url` matching `VAULT_PUBLIC_URL` (default `http://localhost:4002`). |
| `use` fails with `ENOENT … agent.key`                                                        | Run `use` from the directory where you registered, or pass `--key <path>`.                                                                                                                                                                                                                                                                     |
| `custos register` fails with a 502                                                           | The revocation service isn't running. Identity needs it to reserve the agent's revocation slot, and refuses to create an agent that couldn't be revoked.                                                                                                                                                                                       |
| Calls denied with `REVOCATION_STATE_STALE`                                                   | The vault can't reach the revocation service, so it refuses rather than risk allowing a revoked agent. Start revocation; the vault catches up within ~10 s. It also happens if the two services' clocks differ by more than a few seconds; check both machines' time (`REVOCATION_LIST_MAX_CLOCK_SKEW_SECONDS`).                               |
| `use` fails with a 404 `UNKNOWN_TOOL`                                                        | The tool's password isn't in the vault (or the tool name is misspelled). Run the seed command in step 3.                                                                                                                                                                                                                                       |
| `use` fails with a 500 `invalid tag`                                                         | The stored tool password was encrypted under a different `VAULT_MASTER_KEY`: the vault was restarted with a new key. Re-run the seed commands in step 3.                                                                                                                                                                                       |
| Windows: Docker can't bind port 5433 (`access permissions`, not "in use")                    | Windows NAT reserved the port. From an **elevated** shell: `net stop winnat`, `netsh int ipv4 add excludedportrange protocol=tcp startport=5433 numberofports=1 store=persistent`, `net start winnat`.                                                                                                                                         |
| Something else already uses 5432                                                             | Expected. Custos's Postgres uses **5433** on purpose.                                                                                                                                                                                                                                                                                          |

---

## Development

```bash
pnpm test        # unit + integration (databases from `pnpm dev` must be up, and migrated)
pnpm test:e2e    # full lifecycle across real services
pnpm lint
pnpm typecheck
```

The test suite includes negative cases for every security control: a tampered credential, an expired token, a revoked agent, an unknown signing key, and a tool outside the allowlist are each proven to fail.

### Using AWS KMS for the issuer key

In production the identity service signs credentials with an AWS KMS key instead of a seed. The private key is created inside KMS and can never be read out.

1. Create an Ed25519 signing key:

   ```bash
   aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY --description "Custos issuer key"
   ```

2. Give the identity service's AWS identity `kms:GetPublicKey` and `kms:Sign` on that key, and nothing else.
3. Start identity with it. AWS region and credentials come from the standard AWS configuration (`AWS_REGION`, `AWS_PROFILE`, instance role, and so on):

   ```bash
   export IDENTITY_KEY_PROVIDER=kms
   export IDENTITY_ISSUER_KMS_KEY_ID=<key id or ARN>
   pnpm --filter @custos/identity start
   ```

Identity reads the key at boot and refuses to start if it can't, so a wrong key ID or missing permission shows up straight away, not at the first registration.

To check a key end to end (real KMS signatures verified by Custos's own code; creates nothing):

```bash
CUSTOS_TEST_KMS_KEY_ID=<key id or ARN> pnpm --filter @custos/kms test:kms
```

### Using AWS KMS for the audit key

The audit service seals its ledger with its own key (ADR 0017), a separate key again. Create it the same way, give the audit service's AWS identity `kms:GetPublicKey` and `kms:Sign` on it, and start the service with `AUDIT_KEY_PROVIDER=kms` and `AUDIT_SIGNING_KMS_KEY_ID=<key id or ARN>`. It signs at most one seal every `AUDIT_SEAL_INTERVAL_MS` (default 10 s), however busy the log is; recording an entry never calls KMS.

### Using AWS KMS for the revocation key

The revocation service signs every revocation notice and its status list. In production that key lives in KMS too ([ADR 0016](./docs/adr/0016-revocation-signing-key-in-kms.md)). It is a separate key from the issuer key. Create it the same way, give the revocation service's AWS identity `kms:GetPublicKey` and `kms:Sign` on it, and start the service with:

```bash
export REVOCATION_KEY_PROVIDER=kms
export REVOCATION_SIGNING_KMS_KEY_ID=<key id or ARN>
pnpm --filter @custos/revocation start
```

The cross-company publisher (`custos-admin publish-status`) signs as the revocation service, so it uses **the same key**. Give the operator's AWS identity `kms:GetPublicKey` and `kms:Sign` on it, then:

```bash
export CUSTOS_PUBLISHER_KEY_PROVIDER=kms
export CUSTOS_PUBLISHER_KMS_KEY_ID=<the same key id or ARN>
```

The revocation service reuses a signed status list for `REVOCATION_STATUS_REUSE_MS` (default 5 s) while it hasn't changed, so anonymous requests can't each cost a KMS signature. A new revocation is signed straight away.

## Repository layout

- `apps/`: `cli` (the `custos` command) and `dashboard`
- `packages/`: `core` (crypto, DIDs, credentials; pure, no I/O), `sdk`, `contracts`, `connectors` (per-tool adapters), `federation` (accepting another organisation's agents), `kms` (the AWS KMS signer), `config`, `observability`, `testing`
- `services/`: `identity`, `vault`, `revocation`, `audit`
- `infra/`: Docker Compose and database migrations
- `docs/`: build plan, architecture decision records (`docs/adr/`), progress log

Engineering standards and architecture rules: [CLAUDE.md](./CLAUDE.md). Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md). Security issues: [SECURITY.md](./SECURITY.md).

## License

Custos is open source under the [Apache License 2.0](./LICENSE). See [NOTICE](./NOTICE) and, for the reasoning, [ADR 0011](./docs/adr/0011-open-source-apache-2.md).

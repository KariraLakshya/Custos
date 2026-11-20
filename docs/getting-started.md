# Running Custos by hand

The [README](../README.md) quickstart starts everything with one command, `pnpm demo`. This guide does the same thing by hand, one service per terminal, so you can see what each piece needs. It is the path the first-time-reader check ([`readme-test.md`](./readme-test.md)) follows. It ends with the SDK, and with running the same stack from container images.

About 10 minutes. By the end you will have registered an agent, watched it be refused, granted it one tool, used that tool without ever seeing its password, cut it off, and verified the signed audit trail of all of it. If something goes wrong, see [troubleshooting](./troubleshooting.md).

## What you need

- **Node 22** or later
- **pnpm 9**: `npm install -g pnpm@9.15.0`
- **Docker Desktop**, running. It doesn't start by itself; open it first.
- **A shell:** bash/zsh (macOS, Linux, Git Bash) or **PowerShell 7+** on Windows. Windows PowerShell 5.1 mangles the JSON arguments used below.

Every command runs from the repository root.

## 1. Install, start the databases, build

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

## 2. Start the services

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

## 3. Give the vault the tool passwords

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

## 4. Walk through an agent's life with the CLI

Stay in the terminal from step 3: `register`, `grant` and `revoke` read your operator key from `CUSTOS_OPERATOR_KEY`. (They read it only from the environment, never a command-line flag, so it stays out of your shell history.) Using a tool doesn't need it: an agent never holds an operator key.

Make `custos` a shortcut for this terminal:

```bash
alias custos="node apps/cli/dist/bin.js"                  # bash / zsh
```

```powershell
function custos { node apps/cli/dist/bin.js @args }      # PowerShell
```

**Register an agent.** The CLI generates the agent's keypair **on your machine**, proves to the identity service that it holds the private key, and gets back a credential the identity service signs, naming the agent and its public key:

```bash
custos register
```

This writes two files:

- **`agent.key`**: the agent's private key. It never leaves your machine; it isn't sent to Custos and isn't printed. `register` won't overwrite an existing `agent.key` or `agent.json`.
- **`agent.json`**: the agent's credential.

The first line of the output gives the agent's id (`Registered agent <id>.`); you'll need it to grant tools and to revoke the agent. Add `--name billing-bot` to give the agent a name (`Registered billing-bot (id <id>).`). A name is only shown beside the agent: names don't have to be unique, so commands still take the id. `register`, `grant` and `revoke` take `--json` for machine-readable output. Keep `agent.key` private and don't share it; it's gitignored. `agent.json` on its own is useless to anyone who copies it: every access request must be signed with `agent.key`, so without the key the vault refuses (`Code: INVALID_PROOF_OF_POSSESSION`).

**Check the credential independently.** This fetches the identity service's public identity document fresh and verifies the credential's signature itself, rather than trusting the server's word:

```bash
custos verify agent.json
# verified: credential is authentic
```

**Try to use a tool. It's refused.** Custos denies by default: being registered doesn't mean being allowed.

```bash
custos use mock-database query --input '{"table":"customers"}'
# Refused: This agent has not been given this tool.
# Next: To allow it, an operator runs: custos grant mock-database --to <id>
# Code: POLICY_DENIED
```

**Grant exactly one tool, then try again:**

```bash
custos grant mock-database --to <id>
custos use mock-database query --input '{"table":"customers"}'
# { "result": [ { "id": 1, "name": "Ada Lovelace" }, { "id": 2, "name": "Alan Turing" } ] }
```

Behind that one command, the agent showed its credential to the vault, **signed the request with `agent.key`** to prove the credential is its own, and got a pass valid for 60 seconds and for this one tool and action. The vault then made the call using the real password. The agent never saw it. (`use` reads `agent.key` by default; pass `--key <path>` for another agent.)

**The grant covers only that tool.** Slack is still refused:

```bash
custos use mock-slack post-message --input '{"channel":"#ops","text":"hi"}'
# Refused: This agent has not been given this tool. … Code: POLICY_DENIED
```

**Let the agent hand part of its access to a helper agent.** Register a second agent, then have the first one pass on just `query` on the database. The first agent signs this note with its own key, and nothing is sent anywhere. Use the helper's id from its registration output:

```bash
custos register --out helper.json --key-out helper.key
custos delegate mock-database query --to <helper id>
# Agent <helper id> may now query on mock-database for this agent. Give it delegation.json.
custos use mock-database query --credential helper.json --key helper.key --delegation delegation.json
# { "result": [ ... ] }
```

The helper has no grant of its own. It acts on yours, and only for what you passed on. Asking for anything else is refused with `Code: DELEGATION_DENIED (NOT_COVERED)`. The audit log records the whole chain, from the operator who granted the tool through the first agent to the helper, and `custos audit-log` checks every signature in it again. Revoking the first agent (next step) cuts off the helper as well.

**Revoke the agent.** Use the `id` from registration:

```bash
custos revoke <id> --reason "compromised"
```

`Vaults told now: 1.` in the output (`"broadcast": { "delivered": 1 }` with `--json`) means the signed revocation notice was pushed straight to the vault; nobody has to wait for it to check. The dashboard shows the agent as cut off.

**Try again. It's refused everywhere:**

```bash
custos use mock-database query --input '{"table":"customers"}'
# Refused: This agent, or an agent it is acting for, has been cut off from every tool.
# Next: A revoked agent cannot be restored. Register a new one with: custos register
# Code: AGENT_REVOKED
```

**Check the agent.** `custos status` answers "who is this, what may it do, is it cut off, and what did it do lately" in one go:

```bash
custos status <id>
# unnamed (did:web:localhost%3A4001:agents:3f2b8c1e…) (id <id>)
#   Registered … by dev-operator.
#   May use:
#     mock-database, granted … by dev-operator
#   Cut off: yes, at … by dev-operator.
#   Reason: compromised
#   Recent actions, newest first (the audit log verified):
#   …
```

An agent registered with `--name billing-bot` shows that name instead. It reads the identity service, the vault, the revocation service and the audit log with your operator key, which needs the four read scopes (`pnpm demo`'s key has them). Anything it could not read is shown as "could not check", never as "no tools" or "not cut off", and the command then exits 1. The recent actions come from the same checked audit log as `custos audit-log` below; if that log fails its check, `status` says so and shows none of it. `--json` gives the same answer for scripts.

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

## 5. Do the same from code with the SDK

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

## Stopping

Stop each service with Ctrl+C, then `pnpm dev:down` to stop the databases. Data persists in a Docker volume between runs.

## Run from container images

The same stack also runs from Docker images instead of steps 1 to 3: the services, migrations, `custos-admin` and the `custos` CLI all run in containers, so they need no Node on your machine. Starting them still goes through pnpm scripts, and `images:up` is a bash script (on Windows, Git Bash must be on your `PATH`).

```bash
pnpm images:build   # build the images: four services, the dashboard, and a tools image
pnpm images:up      # write dev secrets, migrate, create keys, start everything, store the stand-in tools
```

When it finishes, the services are on the usual ports and the dashboard is at http://localhost:4005. `mock-database` and `mock-slack` are already in the vault. Do step 4 in a shell inside the tools container, where the operator key and the seal server's read-only user are already set and `custos` is on the path (skip the alias). The files `register` writes stay in that container and go when it is removed:

```bash
docker compose --env-file infra/docker/images.env -f infra/docker/docker-compose.yml --profile images exec tools bash
```

The image stack uses the same databases as `pnpm demo` and signs with its own audit key, so switching between them is a key rotation: the first `custos audit-log` after a switch asks you to confirm the new key with `--accept-key` (see ADR 0017, "Key rotation"). A tools container that has never checked the log asks once for each key already in it.

`pnpm images:down` stops and removes the Custos containers; `pnpm dev:down` stops everything, databases included.

The first `images:up` writes random seeds and API keys to `infra/docker/images.env`. They reach the containers only when they start, never an image. The file is gitignored: don't commit or share it. Delete it to start over with new ones; credentials issued under the old seeds then stop verifying.

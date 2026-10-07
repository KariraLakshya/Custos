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
| 1   | `pnpm --filter @custos/audit start`     | 4004 | Stores and signs the audit trail                                |
| 2   | revocation, see below                   | 4003 | Tracks which agents are revoked; pushes revocations out         |
| 3   | identity, see below                     | 4001 | Registers agents and issues their identity credentials          |
| 4   | vault, see below                        | 4002 | Holds the real tool passwords and makes calls on agents' behalf |
| 5   | `pnpm --filter @custos/dashboard start` | 4005 | Live view of every decision                                     |

Revocation, identity and the vault each need their service key from step 1: they use it to write to the audit log, so every admin action is recorded with who did it. **Paste that service key line into the terminal first**, then start the service. A service started with a missing, revoked or wrongly scoped service key refuses to start.

```bash
# revocation's terminal, after pasting its REVOCATION_SERVICE_KEY line
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

**Pull the audit trail.** Every attempt above, allowed or refused, was recorded and signed. The CLI checks each record's signature against the audit service's published key and exits non-zero if any fails:

```bash
custos audit-log
```

Your own admin actions are in it too: registering the agent, granting the tool, storing the passwords and revoking the agent each appear with a `principal` naming the key that did it (`dev-operator`), alongside the agent's own actions.

Pass an agent's DID (the `"did"` from registration) to see just that agent: `custos audit-log <did>`.

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

## Troubleshooting

| Symptom                                                                                      | Cause and fix                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm dev` fails with `failed to connect to the docker API`                                  | Docker Desktop isn't running. Start it and wait until it's ready.                                                                                                                                                                                                                                                                              |
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
| Calls denied with `REVOCATION_STATE_STALE`                                                   | The vault can't reach the revocation service, so it refuses rather than risk allowing a revoked agent. Start revocation; the vault catches up within ~10 s.                                                                                                                                                                                    |
| `use` fails with a 404 `UNKNOWN_TOOL`                                                        | The tool's password isn't in the vault (or the tool name is misspelled). Run the seed command in step 3.                                                                                                                                                                                                                                       |
| `use` fails with a 500 `invalid tag`                                                         | The stored tool password was encrypted under a different `VAULT_MASTER_KEY`: the vault was restarted with a new key, or `pnpm test` / `pnpm test:e2e` ran against the same database and stored test secrets. Re-run the seed commands in step 3.                                                                                               |
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
CUSTOS_TEST_KMS_KEY_ID=<key id or ARN> pnpm --filter @custos/identity test:kms
```

## Repository layout

- `apps/`: `cli` (the `custos` command) and `dashboard`
- `packages/`: `core` (crypto, DIDs, credentials; pure, no I/O), `sdk`, `contracts`, `connectors` (per-tool adapters), `config`, `observability`, `testing`
- `services/`: `identity`, `vault`, `revocation`, `audit`
- `infra/`: Docker Compose and database migrations
- `docs/`: build plan, architecture decision records (`docs/adr/`), progress log

Engineering standards and architecture rules: [CLAUDE.md](./CLAUDE.md). Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md). Security issues: [SECURITY.md](./SECURITY.md).

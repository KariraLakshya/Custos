# Custos

**A trust layer for AI agents.** Open source, early stage. [custoss.dev](https://custoss.dev)

AI agents increasingly call real tools (databases, Slack, payment APIs) on someone's behalf, usually holding a long-lived password or API key for each. If an agent is compromised, there is no clean way to tell who it was, what it was allowed to do, how to stop it everywhere at once, or what it actually did. Custos answers those questions. Each agent gets its own cryptographic identity; real tool passwords stay in a Custos vault and the agent never sees them; each agent may use only the tools it has been granted; a compromised agent can be cut off from every tool in well under a second; and every action lands in a signed audit log anyone can check.

MCP and A2A define how agents talk to tools and to each other. Custos decides whether an agent should be trusted and what it may do. It runs alongside those protocols rather than replacing them.

**Status:** a working development build that you run yourself on one machine with Docker. It is not hosted, and not hardened for production: [docs/threat-model.md](./docs/threat-model.md) lists what is and isn't protected. A hosted service is the long-term goal; the plan is in [docs/build-plan.md](./docs/build-plan.md).

## What it does

Custos answers six questions on every agent request:

| Question                                     | Built? | How                                                                                                                                                                                                       |
| -------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Who are you?** (identity)                  | Yes    | Each agent gets a key pair and a signed credential: a digital ID card that anyone can check without contacting Custos.                                                                                    |
| **Can I trust you?** (authentication)        | Yes    | Every request is signed with the agent's private key, which never leaves its machine. The agent then gets a pass that lasts 60 seconds and covers one tool.                                               |
| **What may you do?** (authorization)         | Yes    | Deny by default. An operator grants an agent specific tools. An agent can hand part of its access to a helper agent, and the audit log records the whole chain.                                           |
| **What data may you receive?** (data policy) | No     | Not built yet. The audit log records which kinds of data each tool touches, but nothing filters or masks data.                                                                                            |
| **Can I revoke you?** (revocation)           | Yes    | One command cuts an agent off from every tool. The signed notice is pushed to the vault immediately, so the vault does not wait to poll for it.                                                           |
| **Can I prove what happened?** (audit)       | Yes    | Every allow and refusal is written to an audit log. Each entry is linked to the one before it, and the log is signed every 10 seconds, so any edit or deletion is detected. `custos audit-log` checks it. |

Also built, as optional setups: services proving who they are to each other with certificates, administrators signing in with a company account (OpenID Connect), one organisation accepting another's agents even while the issuer is offline (tested on one machine so far), and keeping the identity, revocation and audit signing keys in AWS KMS. The vault's own keys are not in KMS yet.

## Prerequisites

- **Node 22** or later
- **pnpm 9**: `npm install -g pnpm@9.15.0`
- **Docker Desktop**, running. It doesn't start by itself, so open it first.
- **A shell:** bash/zsh (macOS, Linux, Git Bash) or **PowerShell 7+** on Windows. Windows PowerShell 5.1 mangles the JSON arguments used below.

## Quickstart

Clone the repository, then run everything from its root:

```bash
git clone https://github.com/KariraLakshya/Custos.git
cd Custos
pnpm install
pnpm dev        # starts the databases in Docker; wait a few seconds for them
pnpm demo       # migrates, builds, creates keys, starts the four services and the dashboard
```

`pnpm demo` keeps running until you press Ctrl-C. It prints the dashboard address (http://localhost:4005; keep it open, because every allow and refusal appears there live), then two lines to paste into a **new terminal in an empty directory**: one makes the `custos` command work, and one sets your operator key (the admin key that lets you register, grant and revoke).

The keys the demo generates stay in memory and in the database, never on disk. Its API keys expire in 12 hours and are revoked when you stop it. Each run uses new keys, so credentials from an earlier run stop verifying.

Then, in that new terminal, walk an agent through its life:

```bash
custos register                     # prints "Registered agent <id>." and writes agent.json + agent.key
custos use mock-database query --input '{"table":"customers"}'
# Refused: This agent has not been given this tool. ... Code: POLICY_DENIED

custos grant mock-database --to <id>
custos use mock-database query --input '{"table":"customers"}'
# { "result": [ { "id": 1, "name": "Ada Lovelace" }, { "id": 2, "name": "Alan Turing" } ] }

custos revoke <id> --reason "compromised"
custos use mock-database query --input '{"table":"customers"}'
# Refused: This agent ... has been cut off from every tool.   Code: AGENT_REVOKED

custos audit-log                    # every step above, with the signed chain checked
```

The agent never saw the database's password: the vault made the call for it. `agent.key` is the agent's private key; keep it private. If `custos audit-log` stops with `KEY_CHANGED` (each demo run signs with a new audit key), check the key it shows against the `audit seal key` line `pnpm demo` printed, then run `custos audit-log --accept-key <that key>`.

**Going further:**

- [Running Custos by hand](./docs/getting-started.md): each service in its own terminal, every setting explained, the full walkthrough (including checking a credential independently and handing access to a helper agent), the TypeScript SDK, and running from container images.
- [Optional setups](./docs/optional-setups.md): certificates between services, company sign-in, accepting another organisation's agents, and AWS KMS keys.
- [Troubleshooting](./docs/troubleshooting.md).
- Every environment variable: [`.env.example`](./.env.example).

Stop the databases with `pnpm dev:down`.

## Development

```bash
pnpm test        # unit and integration tests (needs `pnpm dev` running and `pnpm migrate` run)
pnpm test:e2e    # the full agent lifecycle across real services
pnpm lint
pnpm typecheck
pnpm build
```

The tests include a failing case for every security control: a tampered credential, an expired pass, a revoked agent, an unknown signing key and a tool outside the agent's grants are each proven to be refused.

## Repository layout

- **`apps/`**
  - `cli`: the `custos` command.
  - `admin`: `custos-admin`, which creates operator and service keys, runs `pnpm demo`, and publishes an organisation's revocation list for others.
  - `dashboard`: a live view of every decision. It only displays; `custos audit-log` is what checks signatures.
- **`packages/`**
  - `core`: cryptography, identities and credentials, with no I/O.
  - `contracts`: shared data shapes and error codes.
  - `sdk`: the TypeScript client.
  - `connectors`: per-tool adapters (two stand-in tools and Stripe).
  - `federation`: accepting another organisation's agents.
  - `audit-client`: reading and checking the audit log.
  - `control-plane-auth`: operator and service API keys.
  - `kms`: AWS KMS signing.
  - `config`, `observability`, `testing`: settings, logging and tracing, and test helpers.
- **`services/`**
  - `identity`: registers agents and issues their credentials.
  - `vault`: holds tool passwords and makes calls on agents' behalf.
  - `revocation`: tracks and broadcasts revoked agents.
  - `audit`: the signed audit log.
- **`infra/`**: Docker Compose and images, database migrations, and local setups for certificates (`mtls`), company sign-in (`sso`) and the audit seal store (`seal-store`).

## Documentation

- [Architecture](./docs/ARCHITECTURE.md): how the pieces fit and why.
- [Architecture decision records](./docs/adr/): one file per major decision, with its reasoning.
- [Threat model](./docs/threat-model.md): what Custos protects against, and what it doesn't yet.
- [Build plan](./docs/build-plan.md): what has been built and what comes next.
- [SECURITY.md](./SECURITY.md): how to report a vulnerability.
- [CONTRIBUTING.md](./CONTRIBUTING.md): how to contribute. The engineering standards and architecture rules are in [Claude.md](./Claude.md).

## License

Custos is open source under the [Apache License 2.0](./LICENSE). See [NOTICE](./NOTICE) and, for the reasoning, [ADR 0011](./docs/adr/0011-open-source-apache-2.md).

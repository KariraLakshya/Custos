# Install and run

This page gets the whole Custos stack running on your machine with two commands. It takes about five minutes.

## What you need

- **Node 22** or later.
- **pnpm 9**: `npm install -g pnpm@9.15.0`.
- **Docker Desktop**, running. It does not start by itself; open it first.
- **A shell:** bash or zsh (macOS, Linux, Git Bash), or **PowerShell 7+** on Windows. Windows PowerShell 5.1 mangles the JSON arguments some commands use.

Every command below runs from the root of the repository.

## Install

```bash
git clone https://github.com/KariraLakshya/Custos.git
cd Custos
pnpm install
```

## Start the databases

```bash
pnpm dev
```

`pnpm dev` starts only the databases, in Docker: Postgres on port **5433** (not the usual 5432, on purpose), Redis on 6379, and a separate Postgres on 5434 that holds copies of the audit log's seals. Wait a few seconds for Postgres to be ready.

## Start Custos with one command

```bash
pnpm demo
```

`pnpm demo` creates the database tables, builds every package, generates fresh keys and starts the five processes:

| Process    | Address                 | What it does                                                    |
| ---------- | ----------------------- | --------------------------------------------------------------- |
| identity   | `http://localhost:4001` | Registers agents and signs their identity credentials           |
| vault      | `http://localhost:4002` | Holds the real tool passwords and makes calls on agents' behalf |
| revocation | `http://localhost:4003` | Tracks which agents are revoked and pushes revocations out      |
| audit      | `http://localhost:4004` | Keeps the audit log as a sealed, tamper-evident ledger          |
| dashboard  | `http://localhost:4005` | A live view of every allow and deny                             |

It stores the two stand-in tools, `mock-database` and `mock-slack`, in the vault, then prints:

- the dashboard address;
- the **audit seal key**, which `custos audit-log` asks you to accept after a restart;
- a line that makes the `custos` command work in another terminal;
- your **operator key** (`CUSTOS_OPERATOR_KEY`), which lets you register, grant and revoke.

It keeps running. Press **Ctrl-C** to stop everything.

::: tip Keys live in memory
Every key `pnpm demo` generates stays in memory and in the database: nothing is written to disk. The API keys expire in 12 hours and are revoked when you stop it. Each run uses new keys, so agents registered in an earlier run stop verifying.
:::

Open **http://localhost:4005** and keep it visible while you follow [Your first agent](/get-started/first-agent).

## Stop

Press Ctrl-C in the `pnpm demo` terminal, then stop the databases:

```bash
pnpm dev:down
```

Data stays in a Docker volume between runs.

## Other ways to run it

- **One service per terminal**, with keys you create yourself: the numbered steps in `docs/getting-started.md` in the repository, which use `pnpm -s custos-admin dev-keys` to make the keys. See the [custos-admin reference](/reference/admin-cli#dev-keys).
- **From container images**, with no Node on your machine: [Run from container images](/how-to/container-images).

If something fails, see [Troubleshooting](/how-to/troubleshooting).

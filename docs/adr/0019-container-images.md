# 0019: Container images for every service, built from the lockfile and run from images alone

**Status:** Proposed 2026-10-30 (Phase 7, packaging; scope and order set by ADR 0018). Accepted when the Phase 7 pull request merges.

## Context

Until Phase 7 the stack ran only from source: `pnpm demo` builds on the host and starts each service with the host's Node. ADR 0018 makes packaging the next phase: every service ships as a container image, and CI brings the stack up from those images alone, with no source mount and no host Node. Choices this phase has to make:

- **Which base image**, and how it stays fixed. A tag like `node:22` moves under you; a moved base is an unreviewed change to every image.
- **How each image gets only its own code.** This is a pnpm 9.15 workspace. Every workspace package exports `./dist/index.js`, so an image needs the built `dist` of its package and of every workspace package it depends on, plus their production dependencies, and nothing else: no sources, tests (test fixtures hold fixed seeds) or dev tooling.
- **How the services find each other.** Each service publishes its did:web document under `localhost:400x` (`did:web:localhost%3A4001`, ...). The vault trusts exactly `did:web:localhost%3A4001` and resolves it by fetching `http://localhost:4001/...`. On a normal per-container network, `localhost` inside the vault is the vault, and every DID would have to change.
- **How secrets get in.** Seeds and keys (CLAUDE.md §4) must never be in an image layer.

## Decision

### 1. One Dockerfile, six targets, one pinned base

`infra/docker/images/Dockerfile` builds `custos-identity`, `custos-vault`, `custos-revocation`, `custos-audit`, `custos-dashboard` and `custos-tools` (tagged `:local`). The base is `node:22-bookworm-slim` **pinned by digest**, named once in a `FROM ... AS node-base` line so Dependabot's `docker` ecosystem (`.github/dependabot.yml`) can propose digest bumps; Node majors are ignored there, since the project targets Node 22 LTS. Debian slim rather than Alpine: glibc, like the CI runner, so the build tooling (turbo's native binary) and any prebuilt dependency behave as they do in CI.

### 2. `pnpm deploy --prod` per image

The builder stage installs pnpm 9.15.0, runs `pnpm install --frozen-lockfile` over the whole workspace, `pnpm build`, then `pnpm --filter @custos/<pkg> deploy --prod /out/<pkg>` for each image. `deploy` writes a self-contained directory: the package, its production dependencies, and its workspace dependencies copied in rather than symlinked. Checked in the builder: `dist` is present for the package and for each injected `@custos/*` dependency, and a resolved version (fastify 5.12.7) matches `pnpm-lock.yaml`. The builder then deletes sources, tests and build configs from each output, so only compiled JavaScript ships.

Alternatives considered: `turbo prune --docker` still needs a per-image install and leaves the workspace layout to copy by hand; copying `dist` folders and running a second install duplicates what `deploy` already does. `deploy` is the smallest thing that works with pnpm 9.15 and a frozen lockfile.

### 3. Runtime images: non-root, no package managers

Each runtime image is the same pinned base with npm, npx, corepack and yarn removed from the running filesystem (they remain in the base image's own layer, so they are absent from the container but not from the saved image), `NODE_ENV=production`, files owned by root and read-only to the `node` user (uid 1000), which the process runs as. Each starts with `node dist/index.js` directly, with no shell entrypoint (a CRLF checkout on Windows would break one). Observed sizes on Docker Desktop (containerd store): 81 to 91 MB per image by `docker image inspect` (`.Size`), 335 to 452 MB by `docker image ls` (disk usage).

### 4. `custos-tools` and migrations

`custos-tools` holds `custos-admin` (API keys, needs `DATABASE_URL`), the `custos` CLI, and `custos-migrate`, which applies `infra/migrations` with drizzle-orm's own migrator (`drizzle-orm/node-postgres/migrator`). That is the migrator `drizzle-kit migrate` itself calls, with the same journal and the same `drizzle.__drizzle_migrations` table, so a database migrated by `pnpm migrate` on the host and by the image are interchangeable. Shipping `drizzle-kit` instead would mean shipping root devDependencies in the image, because no deployable package depends on it. Its command wrappers are written by the Dockerfile, not copied, for the same CRLF reason.

### 5. One network namespace, so `localhost` DIDs stay valid

In compose profile `images`, a minimal container `custos-net` (the tools image running `sleep`) owns the network namespace, publishes ports 4001 to 4005, and every Custos container, including tools, joins it with `network_mode: "service:custos-net"`. Every service is then `localhost:400x` to every other, exactly as in development, so no DID, URL default or trust setting changes. The owner is a do-nothing container rather than one of the services: if the owner restarts, everything joined to it loses its network until recreated, and a service can crash. Postgres and the seal store are reached by service name (`postgres:5432`, `seal-store:5432`), the same compose network the owner sits on.

Consequence: this layout is for a single host (development, CI). A real deployment gives each service a real hostname and sets the DID domain and trust settings to match; that is later-phase work (ADR 0018).

### 6. Secrets only at runtime, each service only its own

Seeds, `VAULT_MASTER_KEY` and API keys live in `infra/docker/images.env`: generated by `infra/docker/images/env.sh` with random values, file mode 600 where the filesystem supports it, gitignored, excluded by `.dockerignore`. `pnpm images:up` creates the API keys with `custos-admin dev-keys` inside `custos-tools` after migrating, and creates them again if the database no longer holds them active. Compose passes each service only the variables it reads, as `pnpm demo` does; an unset secret becomes empty, fails validation, and the service refuses to boot. The seal store's role passwords stay the committed dev placeholders of `infra/seal-store/roles.dev.sql`.

### 7. No registry push

Images are built and tested locally and in CI only. Publishing to a registry is deferred to launch (founder decision, ADR 0018).

## Consequences

- `pnpm images:build`, `pnpm images:up`, `pnpm images:down` run the stack from images on any machine with Docker; `pnpm dev` and `pnpm demo` are unchanged.
- `images:down` stops only the image containers. The images stack shares the `pnpm dev` Postgres volume, so its keys and data persist with it; deleting `images.env` starts over with new seeds.
- Its audit seed differs from `pnpm demo`'s, so switching between the two is an audit key rotation (ADR 0017): the first `custos audit-log` after a switch asks for `--accept-key`.
- Every Phase 7 DONE criterion is checked by `pnpm images:check` (`infra/docker/checks/`, each check with a self-test proving it can fail) and runs in CI's `images` job. The layer scan reports PEM keys inside ELF binaries (Debian's `libgnutls`, `gpgv` embed test vectors) as information, not failures; text files are fully checked.
- On Windows, pnpm runs `bash` through `cmd.exe`, which finds WSL's `bash.exe` first, so the scripts run under WSL there; this works when Docker Desktop's WSL integration is on.
- The base digest must be bumped deliberately (Dependabot proposes it); an image build never picks up a new base silently.
- A new workspace dependency needs no Dockerfile change: `deploy` follows the manifests.
- The single-namespace layout does not carry over to multi-host deployment, by design (§5).

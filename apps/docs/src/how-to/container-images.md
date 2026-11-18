# Run from container images

The whole stack also runs from Docker images: the four services, the dashboard, migrations, `custos-admin` and the `custos` CLI all run in containers, so your machine needs no Node. Starting them still goes through pnpm scripts, and `images:up` is a bash script (on Windows, Git Bash must be on your `PATH`).

## Build and start

```bash
pnpm images:build   # build the images: four services, the dashboard, and a tools image
pnpm images:up      # write dev secrets, migrate, create keys, start everything, store the stand-in tools
```

One Dockerfile builds six images, `custos-{identity,vault,revocation,audit,dashboard,tools}:local`, on a Node 22 base pinned by digest. Each holds only production dependencies, runs as an unprivileged user, and has npm and corepack removed from its running filesystem.

When it finishes, the services are on the usual ports and the dashboard is at `http://localhost:4005`. `mock-database` and `mock-slack` are already in the vault.

## Use the CLI inside the tools container

The tools container has `custos` on its path, and the operator key and the seal store's read-only user already set:

```bash
docker compose --env-file infra/docker/images.env -f infra/docker/docker-compose.yml --profile images exec tools bash
```

Then follow [Your first agent](/get-started/first-agent) from step 2, without the alias. The files `register` writes stay in that container and go when it is removed.

## Secrets

The first `images:up` writes random seeds and API keys to `infra/docker/images.env`. They reach the containers only when they start, never an image. The file is gitignored: don't commit or share it. Delete it to start over with new ones; credentials issued under the old seeds then stop verifying.

## Stop

```bash
pnpm images:down    # stop and remove the Custos containers
pnpm dev:down       # stop everything, databases included
```

## Switching between images and `pnpm demo`

The image stack uses the same databases and ports as `pnpm demo`, so run one at a time (`pnpm images:down` first). It also seals the audit log with its own key, so the first `custos audit-log` after a switch asks you to confirm the new key with `--accept-key`. A tools container that has never checked the log asks once for each key already in it.

`pnpm images:check` runs the checks CI runs against the image stack.

Source: ADR 0019.

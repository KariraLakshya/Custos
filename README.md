# Custos

A trust layer for AI agents: cryptographic identity, short-lived scoped credentials, sub-second revocation, and a verifiable audit trail for every agent action.

See [CLAUDE.md](./CLAUDE.md) for architecture invariants and engineering standards, and [docs/build-plan.md](./docs/build-plan.md) for phase order and current status.

## Status

Phase 0 — foundations and scaffolding. No agent identity or credential features exist yet.

## Getting started

Requires Node 22 and pnpm (`corepack enable` or `npm i -g pnpm`).

```bash
pnpm install
pnpm dev      # Postgres + Redis via Docker Compose
pnpm test     # unit + integration
pnpm build
```

## Repository layout

- `apps/` — deployable entry points (CLI)
- `packages/` — libraries shared across services (`core`, `contracts`, `sdk`, `connectors`, `observability`, `config`, `testing`)
- `services/` — long-running processes (`identity`, `vault`, `revocation`, `audit`)
- `infra/` — Docker Compose and database migrations
- `tooling/` — shared TypeScript, ESLint, and Vitest configuration
- `docs/` — build plan, PRD/BRD, architecture diagrams, ADRs

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Security issues: see [SECURITY.md](./SECURITY.md).

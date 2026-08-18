# Contributing

## Setup

```bash
pnpm install
pnpm dev
```

## Workflow

- Conventional Commits for commit messages.
- Small, single-purpose PRs.
- Run `pnpm lint`, `pnpm typecheck`, and `pnpm test` before opening a PR — CI enforces all three plus coverage thresholds (95% lines/branches in `packages/core`, 80% elsewhere).
- Every security-relevant change needs a negative test (tampered/expired/revoked/unauthorized case), not just the happy path.
- Record a [Changeset](https://github.com/changesets/changesets) (`pnpm changeset`) for any release-worthy change.
- New dependencies need a stated justification; prefer a primitive over a convenience wrapper.
- Consequential decisions (new dependency of substance, protocol/format choice, persistence or crypto change) get an ADR in `docs/adr/`.

## Scope

This project builds strictly in the order set by [docs/build-plan.md](./docs/build-plan.md). If a change seems to need something from a later phase, say so instead of building it — see [CLAUDE.md](./CLAUDE.md) §2.

## Code of conduct

Be respectful and constructive. Report unacceptable behavior to lakshya@capmobfinance.com.

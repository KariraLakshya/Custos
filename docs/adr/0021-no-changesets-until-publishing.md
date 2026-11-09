# 0021: No Changesets until packages are published

**Status:** Accepted 2026-11-09 (founder's decision).

## Context

CLAUDE.md §5 named Changesets for versioning and release, and the scaffold set it up: a `.changeset/` folder, `@changesets/cli`, a `pnpm changeset` command, and a `release.yml` step (`changesets/action` v1) that turns recorded changesets into a "Version Packages" pull request.

Every package is `private`, and nothing is published. The first changeset was merged with PR #122 (Phase 8). The release step then failed twice:

1. **Pushing its branch.** The push ran the husky pre-push hook, which runs the full tests. The release runner has no Postgres, so the push was refused. PR #123 fixed this with `HUSKY: "0"`.
2. **Opening its pull request.** The repository does not let workflows open pull requests. GitHub controls this with one switch, "Allow GitHub Actions to create **and approve** pull requests". Turning it on would also let any workflow approve a pull request. That could satisfy `main`'s required review without a person reading the change, which is a real weakening for a security product.

The only output of all this would have been version numbers in `package.json` files that nobody consumes.

## Decision

Remove Changesets until the first package is published:

- delete `.changeset/`, `@changesets/cli` and the `changeset` script;
- `release.yml` keeps the build and the SBOM, and its token drops to `contents: read`;
- drop Dependabot's two `changesets` ignore rules;
- update CLAUDE.md §5, §6, §8 and §9 and CONTRIBUTING.md to match;
- delete the stale `changeset-release/main` branch.

Conventional Commits stay. Until publishing, user-visible changes are noted in the pull request description, and `docs/progress.md` remains the plain-language record.

## Consequences

- There are no version bumps or changelogs for now. Packages stay at `0.0.0`.
- The workflow-PR switch stays off, so every change to `main` still needs a human review.
- One fewer dev dependency: `@changesets/cli` and its tree. It was the last route to `braces` (GHSA-vfj7-8cjw-p6xm, no patched release). With it gone, `braces` is out of the lockfile, so the `pnpm.auditConfig.ignoreGhsas` entry for it is removed and `pnpm audit` passes with no exception.
- **When publishing starts,** reintroduce versioning in a new ADR, without turning the switch on. Options include a personal access token or GitHub App limited to opening that one PR, a release workflow that tags without a PR, or opening the version PR by hand.

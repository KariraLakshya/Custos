# 0023: A static documentation site in `apps/docs`, built with VitePress

**Status:** Proposed 2026-11-18 (branch `docs/site`). The lead decided the location (`apps/docs`, `@custos/docs`, private) and that the site is a static build; this ADR records the choice of generator.

## Context

Custos's documentation is a long README, ADRs and a threat model. The founder wants a real documentation website in the style of LangChain and LangGraph: navigation, search, conceptual pages, tutorials, how-to guides and reference.

Constraints, from `CLAUDE.md` §4 (dependencies are attack surface) and the lead:

- `pnpm audit --audit-level=high` still exits 0;
- versions pinned exactly, and as few dependencies as possible;
- local, offline search: no third-party search service;
- no telemetry;
- builds on Node 22 with pnpm workspaces;
- does not break the root `pnpm.overrides`, in particular `vite@>=7.0.0 <7.3.7`.

The refusal-codes reference must not drift from `packages/contracts/src/refusals.ts`.

## Decision

**VitePress `2.0.0-alpha.17`, pinned exactly, as a devDependency of `apps/docs`.** Markdown content in `apps/docs/src`, configuration in `apps/docs/.vitepress/config.mts`, output in `apps/docs/dist` (so Turborepo's existing `outputs: ["dist/**"]` and the root `.gitignore`'s `dist/` cover it). Search is VitePress's built-in local index (MiniSearch), built into the site and searched in the browser.

The refusal-codes page is generated at build time: a Markdown-it rule replaces a placeholder with tables rendered from `REFUSALS` and `REFUSAL_REASONS` (`apps/docs/lib/refusals.ts`, unit-tested). It runs in the Markdown pipeline, so the dev server, the build and the search index all see the same text, and a new catalogue entry appears on the next build with no hand edit.

Each candidate was installed in a scratch directory and audited (2026-11-18), then the chosen one was installed in the workspace and audited with the real overrides:

| Candidate                         | Packages installed (alone)              | `pnpm audit --audit-level=high`             | Notes                                                                                                                                                                                                      |
| --------------------------------- | --------------------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| VitePress 1.6.4 (latest stable)   | 126                                     | **fails**: vite 5 (GHSA-587h-7wmj-h5pm)     | vite 5 is end of life; fixing it needs a new override                                                                                                                                                      |
| VitePress 2.0.0-alpha.21 (latest) | 105                                     | only the already-ignored picomatch advisory | Uses **vite 8**. In the workspace, pnpm then resolved every package's `vitest` peer to vite 8.3.8 instead of 7.3.7, with unmet-peer warnings: a silent change to the whole repo's test toolchain. Rejected |
| **VitePress 2.0.0-alpha.17**      | **89 new in the workspace** (0 removed) | **exit 0, same advisories as before**       | Uses vite `^7.3.1`, which resolves to the repo's existing 7.3.7 under the override. One vite in the workspace; vitest unchanged                                                                            |
| Starlight 0.43.1 + Astro 7.4.12   | 265                                     | only picomatch                              | vite 8 (same peer problem), native `sharp` and `pagefind` binaries, Astro telemetry on by default (must be disabled), released 5 days earlier (under the workspace's 7-day `minimumReleaseAge`)            |
| Docusaurus 3.10.2                 | 1153                                    | **fails**: 2 critical, 2 high               | Webpack and React; local search needs a third-party plugin                                                                                                                                                 |

VitePress has no telemetry (no reference to it in the package). Its default theme bundles its fonts, so the built site loads no web fonts. The built site references no search service: `@docsearch/*` is installed with VitePress but only used when `search.provider` is `algolia`. The one external URL in the theme bundle (`api.iconify.design`) is a fallback for social-link icons, which this site does not configure.

_Update (2026-11-25, founder):_ the public site shows only what Custos is and how to run it. The Concepts pages (architecture and internals) and the Security section are removed, and the site no longer links to the ADRs, the build plan or the threat model; those stay in the repository. The site's content is to be revisited after the dashboard is live.

## Consequences

- **A pre-release generator.** VitePress 2 has been in alpha since 2025, and alpha.17 (2026-03) is not the newest alpha. Configuration may change before 2.0. The exit is cheap: content is plain Markdown with VitePress containers, and only one page uses generated content. Moving to VitePress 2.0 stable once its vite range is compatible with the root override, or to Starlight, would mean rewriting `config.mts` and the generator hook, not the pages.
- **Upgrading past alpha.17 is blocked by vite 8** until the repo moves its own vite and vitest to 8, or adds a scoped override. Dependabot will propose newer alphas; check `pnpm why vite` before accepting one.
- 89 packages enter the lockfile (Vue, Shiki, MiniSearch, VueUse, Markdown tooling). They are devDependencies of a private app and ship in no service or image.
- `pnpm build` now builds the site (about 6 s). `pnpm test` runs one fast unit test file in `apps/docs`; it needs no database.
- Broken internal links fail the build. Links to `http://localhost:…` are allowed, since they point at the reader's own stack.
- Every fact on the site must match the code on `main`. Pages cite the source file or ADR they come from; reference pages (CLI, HTTP, configuration) need updating when those files change, except the refusal codes, which are generated.
- Publishing is a separate decision: the build is a folder of static files that any static host can serve.

## Alternatives considered

- **VitePress 1.6.4** (stable): fails the audit through vite 5.
- **VitePress 2.0.0-alpha.21**: brings vite 8 and changes the whole repo's test toolchain.
- **Starlight (Astro)**: 2.5 times the packages, native binaries, telemetry to disable, the same vite 8 problem.
- **Docusaurus**: over 1,100 packages and critical advisories; local search is a community plugin.
- **No generator** (a hand-written Markdown-to-HTML script): the fewest packages, but navigation, search, code highlighting and theming would be custom code to maintain, which is its own attack surface.

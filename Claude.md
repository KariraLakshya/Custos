# CLAUDE.md — Custos

Engineering instructions for Claude Code working on this repository. Read fully before writing code.

Three sources govern this project:

- **`docs/build-plan.md`** — phase order and completion criteria. Authority on _when_ and _what's next_. Markdown because it is updated as phases complete. Visual companion: `docs/build-plan.drawio`.
- **`docs/prd.pdf`** — features, requirements, and rationale. Authority on _what_ and _why_. Read-only reference; consult when a requirement is unclear rather than on every task. `docs/brd.pdf` covers business context and is rarely needed for implementation.
- **This file** — architecture invariants, security rules, structure, engineering standards. Authority on _how_.

The reference documents are PDFs. Read them when you need a requirement or rationale, not routinely — they are expensive to parse and their operative content is summarised here and in the build plan. Never attempt to edit a PDF; if a requirement changes, raise it and record the change in an ADR.

Note: the PDFs and diagrams predate the project being named **Custos** and refer to it as _AgentID_. Same project. Use Custos in all code, docs, and output.

General coding behaviour (simplicity, surgical changes, goal-driven execution) is imported below and applies to every task:

@instructions.md

Consult the build plan for the current phase before starting any task.

---

## 0. Project state — keep this current

_This section is the handover between sessions. Read it first. Update it before finishing any phase or significant change. It should be enough to start work without re-reading the codebase._

**Current phase:** Phase 0 — Foundations & skeleton (see `docs/build-plan.md`)
**Last updated:** _not yet started_

### Implemented

_Nothing yet — greenfield._

<!-- As work lands, record it here by package/service. One line each. Example:
- `packages/core` — Ed25519 keypair generation, sign/verify, DID document construction. Unit tested, 96% coverage.
- `services/identity` — VC issuance via KeyProvider interface. Local dev key provider only; KMS not wired.
-->

### In progress

_Nothing yet._

### Next up

Scaffold the monorepo per section 2, then Phase 0 criteria in `docs/build-plan.md`.

### Known issues, debt, and deviations

_None yet._

<!-- Record anything a future session would be surprised by: shortcuts taken with a reason, places the code deviates from this file or the build plan, flaky tests, TODOs that matter, decisions deferred. -->

### Gotchas for a new session

_None yet._

<!-- Environment quirks, non-obvious setup steps, commands that must run in a particular order, external accounts or credentials needed. -->

---

## 1. What Custos is

Custos is a trust layer for AI agents. It gives every agent a cryptographic identity, removes long-lived credentials from agents entirely, enforces what each agent may do, revokes a compromised agent across every connected tool in under a second, and produces a verifiable audit trail.

**Positioning:** MCP and A2A define how agents communicate. Custos defines whether they should be trusted and what they are allowed to do. TLS for agentic services — it runs on top of those protocols, it does not replace them.

Six questions answered on every agent request: who are you (identity), can I trust you (authentication), what may you do (authorization), what data may you receive (data policy), can I revoke you (lifecycle), can I prove what happened (audit).

---

## 2. Scope discipline

The long-term architecture is large. `docs/build-plan.md` sequences it and marks the current phase. **Do not build ahead of it.**

If a task appears to require a component from a later phase, stop and say so with reasoning rather than building it. Speculative generality is a defect here, not foresight.

Not to be built until the build plan's current phase calls for it, however architecturally obvious they seem: sidecar/DaemonSet deployment, edge verifiers, eBPF or egress enforcement, Kubernetes manifests or service mesh, TEE/enclaves, data proxy or PII classification or OCR, full OPA/Rego, cross-org federation, multiple deployment modes, multi-region or autoscaling.

Interfaces should be designed so these fit later without rework. Implementations should not exist before they are needed.

### Scaffolding comes first

Before any feature code is written, the repository must be a professional project skeleton. This is the first deliverable, not a background task, and nothing else begins until it is complete and green.

The scaffold includes: the full monorepo structure with pnpm workspaces and Turborepo wired up; shared tooling packages (`tooling/tsconfig`, `tooling/eslint-config`, `tooling/vitest-config`) consumed by every package; Docker Compose bringing up Postgres and Redis for local development; the migration runner configured with an initial empty migration; GitHub Actions CI running and passing; pre-commit hooks (Husky + lint-staged) enforcing lint and format; Changesets initialised; and the standard repository files — `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, `.github/CODEOWNERS`, `.github/dependabot.yml`, issue and PR templates, `.env.example`, `.gitignore`, `.nvmrc`.

Each package created in the scaffold ships with at least one real passing test, so the test harness is proven working end to end from the first commit rather than assumed.

The scaffold is done when a fresh clone runs `pnpm install && pnpm dev && pnpm test` successfully and CI is green on the initial commit.

---

## 3. Architecture invariants

Hold at every phase. Do not trade them for convenience.

**Hot path vs cold path.** The hot path executes on every agent request and must stay fast: local credential verification, in-process policy evaluation, cached revocation lookup. The cold path is infrequent and may be slow: credential issuance, policy updates, revocation broadcast, audit persistence. **No network call to the control plane belongs on the hot path.**

**Push, don't pull.** The control plane pushes policy and revocation state into local caches on change. The hot path reads locally and never blocks on the cold path.

**Verification is local and offline-capable.** Ed25519 verification is microseconds; DID documents and revocation status are cached. A verifier must be able to validate a credential without reaching the issuer.

**Fail closed on security decisions, with bounded staleness.** If a credential cannot be verified, deny. Cache status with a short TTL so a brief control-plane outage does not deny everything. The TTL is explicit configuration, never an accident.

**Audit writes are asynchronous and non-blocking.** No request waits on an audit write. Audit loss is a bug; audit-induced latency is also a bug.

**`packages/core` is pure.** Crypto and data-structure logic only. No I/O, no network, no clock reads outside an injected dependency. Everything depends on core; core depends on nothing.

---

## 4. Security rules (non-negotiable)

This is a security product. These are not preferences.

- **Private signing keys never touch disk, logs, or version control.** Sign through a KMS-shaped interface from the first real credential, with a local development implementation behind the same interface. Never build a plaintext key store intended for later migration — the migration window is itself the vulnerability.
- **Never log secrets.** Log identifiers, decisions, and rule IDs. Never credential contents, tokens, or key material. Redaction is enforced in the logger, not left to callers.
- **Agents never hold raw tool credentials.** Any code path handing an agent a long-lived key is a defect regardless of convenience.
- **Tokens are short-lived and scoped** — default 60s TTL, bound to a specific tool and action set.
- **Audited crypto only.** `@noble/*`. No hand-rolled cryptography, no novel constructions, no exceptions.
- **Expiry and revocation checks are mandatory and not bypassable by configuration.**
- **Every security control has a negative test.** A tampered credential, an expired token, and a revoked agent must each be _proven_ to fail in CI. Happy-path-only tests on a security boundary are incomplete work.
- **Dependencies are attack surface.** No new dependency without a stated justification. Prefer a primitive over a convenience wrapper.

---

## 5. Tech stack

Decisions recorded as ADRs in `docs/adr/`. Changeable with an ADR, not silently.

| Concern                | Choice                                                |
| ---------------------- | ----------------------------------------------------- |
| Language / runtime     | TypeScript (strict), Node 22 LTS                      |
| Monorepo               | pnpm workspaces + Turborepo                           |
| Crypto                 | `@noble/ed25519`, `@noble/hashes`                     |
| Identity               | `did:web`, W3C VC Data Model 2.0, VC Status List 2021 |
| HTTP                   | Fastify                                               |
| Validation / contracts | Zod, shared in `packages/contracts`                   |
| Persistence            | Postgres (Drizzle ORM, versioned migrations)          |
| Cache                  | Redis                                                 |
| Key management         | AWS KMS behind a `KeyProvider` interface              |
| Logging                | Pino, structured JSON, redaction configured           |
| Tracing / metrics      | OpenTelemetry from the first service                  |
| Tests                  | Vitest, with coverage thresholds enforced in CI       |
| Lint / format          | ESLint (flat config) + Prettier                       |
| Versioning / release   | Changesets, semantic versioning, Conventional Commits |
| CI                     | GitHub Actions                                        |
| Local environment      | Docker Compose                                        |

TypeScript over Python because the W3C DID/VC and Ed25519 ecosystem is materially stronger in JS. A Python SDK follows once the TS core is stable.

Postgres and Redis from the start rather than SQLite and in-memory — not because scale demands it now, but because migrating persistence and cache semantics later is expensive and the Docker Compose cost is near zero.

Rust for the enforcement engine is a future optimization justified by measurement, not now.

---

## 6. Repository structure

```
custos/
├── .changeset/
├── .github/
│   ├── workflows/            # ci, release, security
│   ├── ISSUE_TEMPLATE/
│   ├── CODEOWNERS
│   └── dependabot.yml
├── apps/
│   └── cli/                  # custos CLI
├── packages/
│   ├── core/                 # crypto, DID, VC primitives — pure, no I/O
│   ├── contracts/            # shared Zod schemas, types, error taxonomy
│   ├── sdk/                  # developer-facing client
│   ├── connectors/           # per-tool adapters
│   ├── observability/        # logger, tracing, metrics setup
│   ├── config/               # env schema + validation
│   └── testing/              # shared fixtures, test utilities
├── services/
│   ├── identity/             # DID + VC issuance
│   ├── vault/                # tool credentials, scoped token issuance
│   ├── revocation/           # status list, tombstone broadcast
│   └── audit/                # append-only signed records
├── infra/
│   ├── docker/               # Dockerfiles, compose
│   └── migrations/
├── docs/
│   ├── build-plan.md         # phase order + DONE criteria (scope authority, editable)
│   ├── build-plan.drawio     # same, visual
│   ├── prd.pdf               # features, requirements, rationale (reference)
│   ├── brd.pdf               # business context (rarely needed)
│   ├── architecture.drawio   # target architecture (reference)
│   ├── adr/                  # architecture decision records
│   └── api/                  # OpenAPI specs
├── tooling/
│   ├── eslint-config/
│   ├── tsconfig/
│   └── vitest-config/
├── CLAUDE.md
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
└── turbo.json
```

Rules: `apps` are deployable entry points, `services` are long-running processes, `packages` are libraries, `tooling` is shared build configuration. Packages declare explicit `exports` — no deep imports across package boundaries. Do not create directories for work the build plan has not reached.

---

## 7. Engineering standards

**TypeScript.** `strict: true`, `noUncheckedIndexedAccess`, no `any` without an adjacent comment justifying it. Public APIs have explicit return types.

**Errors are values on security paths.** Verification returns a discriminated result, not a thrown exception. Exceptions are for programmer error and infrastructure failure. The error taxonomy lives in `packages/contracts`.

**Testing is mandatory, not optional.** No code is complete without tests. A pull request that adds behaviour without adding tests is unfinished work, regardless of how obvious the behaviour seems. Write the test alongside the code, not after.

Test layers, all of which must exist:

- **Unit** — colocated `*.test.ts` next to source. Pure logic, no I/O. Every exported function in `packages/core` has unit tests covering both success and failure.
- **Integration** — per service, run against real Postgres and Redis from Docker Compose, never mocks of the database. Cover the service's public API surface and its failure modes.
- **End-to-end** — exercise the complete agent lifecycle across services: register, issue credential, obtain scoped token, call tool, revoke, verify denial, inspect audit record.
- **Contract** — every connector is tested against a recorded or sandboxed version of the real tool API, so a connector cannot silently drift.

Security-critical negative tests are required and are treated as first-class, not edge cases. At minimum, prove in CI that a tampered credential fails verification, an expired token is rejected, a revoked agent is denied, a credential signed by an unknown key is rejected, malformed and oversized input is rejected safely, and an agent cannot access a tool outside its allowlist. Happy-path-only testing of a security boundary is incomplete work.

Coverage thresholds are enforced in CI and the build fails below them: `packages/core` at 95% lines and branches, all other packages and services at 80%. Thresholds ratchet upward and are never lowered to make a build pass.

Every bug fix begins with a failing test that reproduces the bug. Tests are deterministic — no reliance on wall-clock time, network, or ordering. Time is injected, randomness is seeded.

**Observability from the first service, not retrofitted.** Structured logs with correlation IDs, OpenTelemetry spans across service boundaries, metrics on decision latency and outcomes.

**Migrations are versioned and reversible.** No ad-hoc schema changes, no destructive migration without an explicit note.

**Configuration is validated at startup.** Zod schema in `packages/config`; the process refuses to boot on invalid environment rather than failing at first request.

**Commits and PRs.** Conventional Commits. Small, single-purpose changes. A change that breaks `pnpm dev`, CI, or the documented demo path is fixed in the same change, not a follow-up.

**ADRs for consequential decisions.** New dependency of substance, protocol or format choice, persistence or crypto change, anything hard to reverse. Short: context, decision, consequences.

**Definition of done** for any unit of work: types pass, lint passes, tests pass including negative cases, docs updated if behaviour changed, no unjustified new dependencies, no secret in logs or history, ADR written if the decision was consequential.

---

## 8. Commands

```bash
pnpm install
pnpm dev              # full local stack via Docker Compose
pnpm test             # unit + integration
pnpm test:e2e
pnpm lint
pnpm typecheck
pnpm build
pnpm migrate
pnpm changeset        # record a release-worthy change
```

These must stay working. A change that breaks any of them is fixed in the same change.

---

## 9. Continuous integration

CI is part of the scaffold, not something added later. It must be green before feature work begins and must stay green.

**`.github/workflows/ci.yml`** — runs on every push and pull request:

- Checkout, install pnpm with store caching, restore Turborepo cache
- `pnpm lint` — ESLint, zero warnings tolerated
- `pnpm typecheck` — strict TypeScript across all packages
- `pnpm test` — unit and integration, with Postgres and Redis as GitHub Actions service containers
- `pnpm test:e2e` — full lifecycle
- Coverage report, failing the build below the thresholds above
- `pnpm build` — every package builds
- Jobs run in parallel where dependencies allow; the workflow fails fast on lint and typecheck

**`.github/workflows/security.yml`** — runs on pull requests and on a weekly schedule:

- `pnpm audit` — fails on high or critical advisories
- Secret scanning (Gitleaks) across the diff and history
- Static analysis (CodeQL or Semgrep) with a security ruleset
- SBOM generation on release builds

**`.github/workflows/release.yml`** — runs on merge to main:

- Changesets version and changelog generation
- Build and publish
- Tagged release with SBOM attached

**Branch protection on `main`:** all CI checks must pass, at least one review, no direct pushes, linear history. Do not add workarounds that let failing code merge — if CI is wrong, fix CI in its own change.

---

## 10. Audit record design

The differentiating direction under exploration is **agent delegation provenance for compliance** — proving which agent, acting under whose authority, accessed what data, in a form an auditor accepts. India's DPDP Act (enforcement from November 2026, full compliance May 2027) mandates role-based access control, continuous audit logs with one-year retention, and data masking, and its data-fiduciary model has no settled answer for autonomous agents.

Consequence for design: every audit record carries the agent identity, the authority chain it acted under, the data categories touched, the policy applied, the decision, and a signature. Retention and export are first-class concerns, not additions.

This shapes the audit schema. It does not change build order. Fuller rationale is in `docs/prd.pdf`.

---

## 11. Token and context efficiency

Session cost is driven by structure, not sentence length — the full transcript is resent every turn, so early clutter is paid for on every later turn.

**Output.** Skip preambles, recaps of the request, and closing summaries. No "I'd be happy to" or "Great question." Short declarative sentences. Run the tool first and show the result rather than narrating intent. Exception below.

**When to explain anyway.** Concision does not override section 1 of `instructions.md` or the working style below. Explain fully when: making an architecture or security decision, working in unfamiliar territory (cryptography, DID/VC, delegation semantics), surfacing a tradeoff or ambiguity, or pushing back. Terse is for routine implementation; hard calls and unfamiliar ground still get reasoning.

**Edits over rewrites.** When changing part of a file, produce a targeted edit, not a full rewrite of an unchanged file.

**Filter command output.** Do not paste thousand-line stack traces, full test-runner output, or broad greps into context. Take the relevant lines. Prefer targeted searches over repository-wide ones.

**Reference documents are expensive.** PDFs and diagrams under `docs/` are excluded from search via `.claudeignore`. Read a PDF only when a specific requirement is genuinely unresolved by this file or the build plan, and read the condensed markdown equivalent when one exists.

**Reasoning effort.** Baseline for routine implementation. Raise it for genuinely hard calls — architectural tradeoffs, crypto or delegation design, subtle bugs — then drop back for the implementation that follows.

**Scope one unit of work per exchange.** Batch genuinely related changes into one pass so they stay consistent. Do not batch unrelated work.

---

## 12. Working style

State the approach before writing significant code. Prefer the smallest change that satisfies the current phase's DONE criteria in `docs/build-plan.md`. Flag scope creep rather than accommodating it.

If something in this file is wrong, outdated, or superseded, say so and update it as part of the change rather than working around it.

### Session handover — required

**Section 0 of this file must be updated before a phase is considered complete**, and whenever something lands that a future session would need to know. This is not optional bookkeeping; it is what makes the next session productive instead of archaeological.

Update it when: a phase completes, a package or service gains meaningful functionality, a dependency or schema changes, a shortcut or deviation is taken, a decision is deferred, or the environment gains a setup step.

When updating, also: advance the **Current phase** line here and in `docs/build-plan.md`, set **Last updated** to the date, move finished items from _In progress_ to _Implemented_, and clear anything in _Known issues_ that has been resolved.

Write it for someone with no memory of the work. Be specific and brief — one line per item, naming the package or service. State what actually exists, not what was intended. If a shortcut was taken, say what and why, because an unrecorded shortcut becomes a silent bug later.

Keep section 0 short. It is a handover note, not a changelog — git history is the changelog. If it grows past roughly a page, compress the _Implemented_ list into per-package summaries.

Write it for a future Claude reading cold, not for a human enjoying prose. Do not wait for a session to become unwieldy — update at each natural checkpoint (feature done, bug closed, phase complete), the same way you would commit at a logical stopping point.

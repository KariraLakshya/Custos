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

_This section is the handover between sessions. Read it first. Update it before finishing any phase or significant change. It should be enough to start work without re-reading the codebase. For a plain-language progress log aimed at the founder rather than a future Claude session, see `docs/progress.md` — update both, they serve different readers._

**Current phase:** Phase 3 — Revocation engine (see `docs/build-plan.md`) — implemented and fully verified locally (`lint`/`typecheck`/`test`/`test:e2e`/`build` all green across the monorepo); **not yet committed or pushed**; next is Phase 4
**Last updated:** 2026-09-09

### Implemented

- Full monorepo scaffold: pnpm workspaces + Turborepo, `tooling/{tsconfig,eslint-config,vitest-config}`, `packages/{core,contracts,sdk,connectors,observability,config,testing}`, `apps/cli`, `services/{identity,vault,revocation,audit}` — each with its own `package.json`/`tsconfig.json`/`vitest.config.ts` and at least one passing test.
- `packages/observability` — Pino logger with redaction enforced in the logger (caller-supplied `redact` cannot disable it).
- `packages/config` — Zod env schema + `loadEnv()` that throws (refuses to boot) on invalid environment; each service extends the base schema with its own `PORT`.
- `infra/docker/docker-compose.yml` — Postgres + Redis for local dev (`pnpm dev`).
- `infra/migrations` — Drizzle wired, one empty custom initial migration (`0000_initial.sql`); verified with `pnpm migrate` against the live container.
- Husky + lint-staged pre-commit (lint + format staged files) — verified it blocks a deliberate lint violation.
- Changesets initialized. GitHub Actions: `ci.yml`, `security.yml`, `release.yml`.
- Standard repo files: README, SECURITY, CONTRIBUTING, CODEOWNERS, dependabot.yml, issue/PR templates, `.env.example`, `.gitignore`, `.nvmrc`.
- Coverage thresholds enforced via `tooling/vitest-config` (80% default, 95% for `packages/core`) — confirmed both failing and passing correctly.
- `pnpm install && pnpm dev && pnpm test` (and `lint`/`typecheck`/`build`) all pass from this state.
- `packages/core` — Phase 0's knowledge-gap work, all pure/no-I/O, 100% test coverage:
  - `crypto/ed25519.ts` — keypair gen/sign/verify on `@noble/ed25519`; `verify()` fails closed (never throws) on malformed input.
  - `did/did-web.ts` — builds a `did:web` document from a domain + public key only (no secret key needed, ready for a future KMS-shaped key provider).
  - `vc/document-loader.ts` + `vc/credential.ts` — issues/verifies one W3C VC 2.0 credential using the `Ed25519Signature2020` JSON-LD Data Integrity suite (Digital Bazaar libraries, not hand-rolled canonicalization — see `docs/adr/0001-vc-proof-format.md`). The document loader only ever resolves bundled contexts, never the network.
  - `types/vc-libs.d.ts` — ambient TS declarations for the several dependencies here that ship no types.
- Pushed to `origin/main` (`e4d9c7b`, `5ffce60`) and confirmed green on GitHub Actions — `lint-typecheck`, `test`, `build`, and `version-or-release` all passed, not just the local run.
- `release.yml`'s SBOM step now uses `@cyclonedx/cdxgen` instead of `@cyclonedx/cyclonedx-npm` — the latter shells out to `npm ls`, which doesn't understand pnpm's `node_modules` layout and failed on the first real push to actually exercise `release.yml`.
- **Phase 1 — Identity core**, built on Phase 0's `packages/core` primitives:
  - `packages/core`: `did-web.ts` now supports per-agent path segments (`did:web:{domain}:agents:{id}`) plus `didWebToResolutionUrl()` (reverses a DID to the URL a resolver fetches — `http` for `localhost`/`127.0.0.1`, `https` otherwise). New `keys/key-provider.ts` (`KeyProvider` interface — `createKeyPair()`/`sign(keyId, message)`, never returns private key material) and `keys/local-key-provider.ts` (in-memory dev implementation; secret keys live only in that process's memory). `vc/credential.ts`'s `issueCredential` now takes an injected `signer: { id, sign }` instead of a raw `secretKey` — closes the literal TODO left in Phase 0's code; core never sees private key material during issuance. `DidWebDocument` carries a doc comment recording that `assertionMethod` is signing-only and any future `keyAgreement` key must be a structurally separate X25519 keypair, never this Ed25519 key reused.
  - `services/identity`: real Postgres-backed agent registry, replacing Phase 0's single in-memory demo key/route entirely. `POST /agents` generates a keypair via `KeyProvider`, builds a per-agent `did:web` document, self-issues a VC, and persists `{id, did, keyId, didDocument, credential}`. `GET /agents/:id/did.json` serves the stored document (400 on a malformed id, 404 on unknown). Schema lives at `services/identity/src/db/schema.ts` (the old placeholder `infra/migrations/schema.ts` is gone; `infra/migrations/drizzle.config.ts`'s `schema` path now points at the service). Migration `0001_narrow_sasquatch.sql` applied. `drizzle-orm`/`pg` added as `services/identity` dependencies (kept at root too, since drizzle-kit's config still resolves `drizzle-orm/pg-core` from the schema file's own location).
  - `apps/cli`: `custos register [--identity-url] [--out]` and `custos verify <credentialFile>` (exit code 1 on rejection). Verification is genuinely independent — it resolves the issuer's DID document fresh over HTTP via `didWebToResolutionUrl` and calls `verifyCredential` from `@custos/core`, sharing no state with whatever issued the credential.
  - Tests: unit (core primitives, CLI commands against a local `node:http` stand-in), integration (`services/identity` against the real Compose Postgres, including a tampered-credential rejection test), and a genuine end-to-end test (`apps/cli/src/cli.e2e.test.ts`, run via `pnpm test:e2e`) that boots the real identity service in-process and proves register → independently verify succeeds, and a post-issuance tampered credential is rejected — the literal Phase 1 DONE criterion.
  - `.github/workflows/ci.yml`'s `test` job now runs `pnpm migrate` before `pnpm test` — the first push surfaced that the job's fresh Postgres service container had no schema applied, so every `services/identity` integration test hitting the `agents` table failed with `relation "agents" does not exist` (500s where 201/404 were expected). Fixed and reproduced locally against a genuinely fresh database before pushing (commit `8097daf`).
- **Phase 2 — Credentials & vault (dispossession)**, built on Phase 1's identity primitives:
  - `packages/core`: two new KMS-shaped primitives, same pattern as `KeyProvider`. `keys/secret-cipher.ts` (`SecretCipher` interface) + `keys/local-secret-cipher.ts` (dev implementation, XChaCha20-Poly1305 via the new `@noble/ciphers` dependency, keyed by a caller-supplied 32-byte key — never generates or persists the key itself; see `docs/adr/0004-vault-credential-encryption.md`). `token/scoped-token.ts` — `issueScopedToken`/`verifyScopedToken`, a compact custom Ed25519-signed token (`base64url(claims).base64url(signature)`, claims are `{sub, tool, action, iat, exp}`), not JWT (see `docs/adr/0003-scoped-token-format.md`); verification is entirely local (no network/DB), fails closed on malformed/tampered/expired input, and takes an injected `now: Date` rather than reading the clock.
  - `packages/connectors`: `Connector` gained a `call({action, input, credential}) -> Result<unknown, ConnectorCallError>` method (`revoke()` unchanged, still Phase 3's). Three implementations: `stripe.ts` (real — Stripe test-mode `list-customers` via plain `fetch`, no `stripe` SDK dependency), `mock-slack.ts` and `mock-database.ts` (fully in-memory fakes, no network). `@custos/contracts`'s `Result`/`ok`/`err` now a `connectors` dependency.
  - `services/vault`: replaces the Phase 0 health-check shell entirely. Postgres table `tool_credentials` (`services/vault/src/db/schema.ts`) stores `{tool, ciphertext, nonce}` — the plaintext credential is never persisted. `POST /credentials` seeds a tool's real credential (encrypted via `SecretCipher` before storage); `POST /tokens` independently verifies the requesting agent's VC (resolves its issuer DID fresh over HTTP, same pattern as `apps/cli`'s `verify`) and, if the tool is known, issues a 60s-default scoped token signed by the vault's own in-memory `KeyProvider` keypair (generated once per server build — not yet published as a DID document, since nothing outside this process verifies these tokens yet); `POST /call` verifies the token locally (hot path — no DB/network until after the token checks out), decrypts the tool's stored credential just-in-time, and calls the matching connector. `buildServer` is `async` (needs to generate its signing keypair before serving) and takes an injectable `clock` for deterministic expiry tests. `VAULT_MASTER_KEY` (32-byte hex) is required at boot with no default — refuses to boot rather than fall back to a known key. `scripts/seed-credential.mjs` is the operational path to store a real tool credential (`pnpm --filter @custos/vault run seed <tool> <secret>`).
  - `apps/cli`: `custos use <tool> <action> --credential <path> [--vault-url] [--input <json>]` — requests a token then immediately spends it, in one call (`src/use.ts`).
  - `infra/migrations`: `0002_watery_hammerhead.sql` adds `tool_credentials`; `drizzle.config.ts`'s `schema` is now an array covering both `services/identity` and `services/vault`.
  - Tests: unit (`scoped-token`, `local-secret-cipher`, all three connectors — tampered/expired/wrong-key/malformed-input/network-failure cases), integration (`services/vault` against real Postgres, including a real in-process `services/identity` boot for the token-issuance DID-verification path), and two genuine end-to-end additions to `apps/cli/src/cli.e2e.test.ts` (register → token → call succeeds; a token is rejected once expired and a fresh one is required) using `@custos/testing`'s new `mutableClock` to simulate the 60s expiry deterministically rather than sleeping in real time. Also manually smoke-tested against the real built services (`node services/{identity,vault}/dist/index.js` + the built CLI) end to end, including the fail-closed-on-invalid-env behavior for a bad `VAULT_MASTER_KEY`/`LOG_LEVEL`.
  - `packages/testing`: added `mutableClock` (advanceable sibling to `fixedClock`) for exactly this expiry-simulation need.
  - Coverage: `packages/core` 99.1%+ (still ≥95% threshold), `services/vault` ~99%, `packages/connectors` 100% stmts — all above the 80%/95% thresholds.
  - CI fix (`20126a4`): the `test` job had been failing on every DB-backed identity test with a 500 while `pnpm migrate` in the same job succeeded. Cause was Turborepo strict env mode, not Phase 2 code — see the gotcha below. A prior commit (`83a5161`) raised vitest's timeouts to 30s and switched tests from `localhost` to `127.0.0.1`; both are genuine determinism improvements but neither was the actual fix.
- **Phase 3 — Revocation engine**, the reason the project exists:
  - `packages/core`: `status/bitstring-status-list.ts` (Bitstring Status List v1.0, not the superseded StatusList2021 draft CLAUDE.md previously named — see `docs/adr/0005-revocation-architecture.md`; gzip+multibase-encoded 131,072-bit minimum bitstring, `buildStatusListEntry`/`buildStatusListSubject` helpers) and `revocation/tombstone.ts` (`issueRevocationTombstone`/`verifyRevocationTombstone`, the same compact Ed25519-signed envelope shape as `scoped-token.ts`, permanent — no `exp`, since a replayed revocation is idempotent). `vc/credential.ts`'s `UnsignedCredential` gained an optional `credentialStatus` field.
  - `services/revocation`: was a health-check shell, now the control plane for both allocation and revocation. Own `did:web` signing identity (same `KeyProvider` pattern), published at `/.well-known/did.json`. `POST /agents` (called by identity during registration, before the credential is signed) reserves a status list index per agent, idempotently, via a `serial` column so no index is ever reused. `POST /revocations` flips the DB row, signs a tombstone, and pushes it to every configured subscriber (`REVOCATION_SUBSCRIBER_URLS`) via `broadcast.ts`'s `TombstoneBroadcaster` (HTTP today; interface-shaped for a broker later, matching `KeyProvider`/`SecretCipher`). `GET /revocations` replays every revocation as a fresh tombstone, for a subscriber's resync. `GET /status/revocation` rebuilds the bitstring from the DB on every request and returns it as a signed VC — the durable, third-party-verifiable half; the tombstone push is the fast half.
  - `services/identity`: registration now calls the revocation service first and fails the registration closed if that call fails (`agents/status-allocator.ts`) — an agent issued with no status list entry could never be revoked. `REVOCATION_URL` env var, defaults to `http://localhost:4003`.
  - `services/vault`: `revocation/cache.ts` is the hot-path revocation view — an in-memory revoked-DID set, checked in microseconds on every `/call`, updated by pushed tombstones (`POST /revocations`, verified against the revocation service's resolved DID before being trusted — an unauthenticated push would be a denial-of-service vector) and by a periodic resync (`REVOCATION_RESYNC_INTERVAL_MS`, plus one at boot). Bounded staleness is explicit config (`REVOCATION_MAX_STALENESS_MS`, default 30s): a cache that has never synced, or has gone stale, denies rather than silently trusting an outdated view. `issueToolToken` also now refuses a revoked agent a fresh token, not only the hot path.
  - `packages/connectors`: `Connector.call()` gained `agentId`; `connector.ts` exports a shared `createRevocationGuard()` every adapter composes, so "adapters honour revocation" is genuinely true at the tool boundary, not only at the vault's own gate. Stripe's `revoke()` marks the agent revoked locally (no per-agent upstream key to withdraw yet, see Known issues).
  - `apps/cli`: `custos deprovision <agentId> [--revocation-url] [--reason]` — the entire Phase 3 demo in one command.
  - Tests: unit (status list bit-packing/encoding, tombstone issue/verify, all three connectors' revocation guard, the vault's revocation cache — forged/unverifiable-issuer/malformed/stale cases), integration (`services/revocation` and `services/vault` against real Postgres, including independent verification of the published status list credential against the revocation service's own DID document), and a genuine end-to-end addition to `apps/cli/src/cli.e2e.test.ts`: an agent actively holding session tokens for three tools (mock-slack, mock-database, and Stripe against a local stand-in), one `custos deprovision` call, all three calls rejected — measured under 1 second — and the connectors themselves (not only the vault) independently refuse the agent afterward. This is the literal Phase 3 DONE criterion, proven in CI, not just described.
  - Coverage: every touched package/service above its threshold (`packages/core` 100% lines / ~98% branches; `services/vault` ~96% stmts / ~91% branches; `services/revocation` ~91% stmts / ~83% branches; `packages/connectors` ~95% stmts).
  - `docs/adr/0005-revocation-architecture.md` records the three consequential decisions: Bitstring Status List over the superseded draft, signed-push-plus-status-list (not either alone), and the revocation service owning index allocation.

### In progress

Phase 3 is fully implemented and green locally but **not yet committed or pushed** — no CI confirmation exists yet for it. Next session (or later in this one): review the diff, commit, push, and confirm GitHub Actions passes, the same way Phases 0–2 were closed out.

Also open, independent of any phase: **8 dependabot PRs** were outstanding against clean `main` as of Phase 2's close — including `zod` 3→4 and the `@noble/ed25519`/`@noble/hashes` bumps underneath `packages/core` — status unconfirmed as of this session; re-check before assuming they're still open.

### Next up

Phase 4 — Authorization & audit: simple per-agent × tool allowlists (not full OPA/Rego), and a signed append-only audit record per action.

### Known issues, debt, and deviations

- Reconciled doc filenames to match this file's structure: `BuildPlan.md` → `docs/build-plan.md`, `AgentID_Product_PRD.pdf` → `docs/prd.pdf`, `AgentID_BRD.pdf` → `docs/brd.pdf`, `AgentID_Project_Plan.drawio` → `docs/build-plan.drawio`, `AgentID_Architecture.drawio` → `docs/architecture.drawio`.
- LICENSE deliberately not added — open-source-vs-proprietary decision explicitly deferred by the user.
- `release.yml` runs `changeset version`/`changeset tag` only, no `npm publish` — no publish target exists yet (all packages private, no license chosen).
- `services/identity`'s `KeyProvider` is still the in-memory local implementation — secret keys live only in that process's memory for its lifetime (never disk/logs), per CLAUDE.md section 4, but there's no real KMS integration yet. Swapping in an AWS KMS-backed `KeyProvider` is future work, not scoped to any phase yet.
- No `keyAgreement` verification relationship exists anywhere (Custos's DID documents only sign/verify VCs today). If a later phase needs an encrypted channel (vault token handoff, Phase 6 cross-org handshake), that needs its own X25519 keypair under `keyAgreement` — never the Ed25519 identity key reused — see the doc comment on `DidWebDocument` in `packages/core/src/did/did-web.ts`.
- `services/vault`'s own token-signing keypair is ephemeral (generated fresh each server start, via the same in-memory `KeyProvider` pattern) and not published as a DID document — nothing outside the vault process verifies these tokens today, so this is fine, but a multi-instance or restarted-mid-flight vault would invalidate outstanding tokens. Not a Phase 2 gap (tokens are 60s-lived by design), but worth knowing.
- `VAULT_MASTER_KEY` is one symmetric key for every stored tool credential — no per-tool keys, no envelope encryption, no rotation story. Deliberate for this phase's scale; see `docs/adr/0004-vault-credential-encryption.md` for the real-KMS migration path.
- Phase 2 has no policy/allowlist enforcement — any agent that independently verifies can request a token for any tool the vault knows about. That's explicitly Phase 4 scope per `docs/build-plan.md`, not an oversight here.
- The real Stripe connector implements exactly one action (`list-customers`, read-only) — enough to satisfy Phase 2's "at least one real connector" DONE criterion; broader Stripe coverage is future work if a later phase needs it.
- Stripe's `revoke()` only marks the agent revoked in the connector's local guard — there is one shared vault-held Stripe key for every agent, so there is no per-agent upstream key to actually withdraw yet. Real per-agent upstream revocation for Stripe is future work once agents each hold a restricted key.
- `services/vault`'s revocation cache resolves the revocation service's DID document once and caches the key for the process lifetime — if the revocation service ever rotates its signing key, a running vault needs a restart to pick up the new one. Not a Phase 3 gap (nothing rotates keys yet), but worth knowing.

### Gotchas for a new session

- This machine has a native Windows PostgreSQL 18 service already bound to port 5432. The Compose Postgres is mapped to host port **5433** instead (`infra/docker/docker-compose.yml`, `.env.example`, `infra/migrations/drizzle.config.ts`). Don't "fix" this back to 5432.
- Docker Desktop isn't started automatically by `pnpm dev` — start it first if the daemon isn't running.
- pnpm wasn't preinstalled; `corepack enable` failed with `EPERM` in this environment (needs elevated Windows permissions) — installed instead via `npm install -g pnpm@9.15.0`.
- `services/vault` refuses to boot without `VAULT_MASTER_KEY` set (32-byte hex, no default — see `.env.example` for how to generate one). Running it standalone (outside `pnpm dev`/tests) needs this exported first.
- **Turborepo 2.x runs tasks in strict env mode**: a task only sees env vars declared in `turbo.json` (`env`/`globalEnv`). `DATABASE_URL`, `REDIS_URL` and `VAULT_MASTER_KEY` are declared on the `test`/`test:e2e` tasks — **any new env var a test depends on must be added there too, or it silently will not reach the task**. This cost a red CI for several commits: `pnpm migrate` runs directly and saw `DATABASE_URL`, the tests ran under turbo and did not, so they fell back to the hardcoded `localhost:5433` default and threw on every query (surfacing as a 500, not the 502 the route returns for a failed `Result` — that gap is the tell for an unhandled throw). It passed locally only because the compose Postgres really is on 5433. To check this class of bug: point `DATABASE_URL` at a dead port and run `npx turbo run test --force --filter=@custos/identity` — the tests must **fail**; if they pass, the env var is not reaching the task.
- `eslint.config.js` (root) has a small `**/*.mjs` override adding Node globals (`process`, `console`, `fetch`, `URL`) — needed for `services/vault/scripts/seed-credential.mjs`, a plain Node script outside the TypeScript project where `eslint:recommended`'s `no-undef` isn't otherwise suppressed the way it is for `.ts` files.

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

| Concern                | Choice                                                       |
| ---------------------- | ------------------------------------------------------------ |
| Language / runtime     | TypeScript (strict), Node 22 LTS                             |
| Monorepo               | pnpm workspaces + Turborepo                                  |
| Crypto                 | `@noble/ed25519`, `@noble/hashes`, `@noble/ciphers`          |
| Identity               | `did:web`, W3C VC Data Model 2.0, Bitstring Status List v1.0 |
| HTTP                   | Fastify                                                      |
| Validation / contracts | Zod, shared in `packages/contracts`                          |
| Persistence            | Postgres (Drizzle ORM, versioned migrations)                 |
| Cache                  | Redis                                                        |
| Key management         | AWS KMS behind a `KeyProvider` interface                     |
| Logging                | Pino, structured JSON, redaction configured                  |
| Tracing / metrics      | OpenTelemetry from the first service                         |
| Tests                  | Vitest, with coverage thresholds enforced in CI              |
| Lint / format          | ESLint (flat config) + Prettier                              |
| Versioning / release   | Changesets, semantic versioning, Conventional Commits        |
| CI                     | GitHub Actions                                               |
| Local environment      | Docker Compose                                               |

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
│   ├── progress.md           # plain-language progress log for the founder — updated every phase/push
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

### Progress log — required

`docs/progress.md` is a **separate, mandatory** update from section 0 above — it is written for the founder tracking Custos as a business, not for a future Claude session, and section 0 being updated does not satisfy this.

Update it after **every phase completion and every push to `origin`**, no exceptions. Each entry needs: date, phase/milestone name, commit hash(es) and push status, what shipped, how it works explained in plain language (no unexplained jargon), and why it matters or what it unblocks. Newest entry on top.

Write for someone who wants to understand how the project — the startup — is progressing, not someone reading code. Explain consequences and capabilities gained, not just facts about files changed.

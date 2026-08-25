# Custos — Progress Log

Plain-language record of what has actually been built, how it works, and why it matters — for tracking Custos as a project, not just as code. Updated after every phase completion and every push to `origin`. Newest entry on top.

This is not the technical handover (that's section 0 of `CLAUDE.md`, written for a future Claude session). This is written for a person tracking the state of the startup.

---

## 2026-08-24 — Phase 1: Identity core

**Commits:** `c3bb05e` — "feat: Phase 1 identity core - per-agent registry, KMS-shaped signing, CLI"; `adfd682` — "fix: run pending migrations before the test job in CI". Both pushed to `origin/main`.

**What shipped:** Phase 0 proved the cryptography worked for one demo agent. Phase 1 turns that into a real system: every agent now gets its own identity, generated and stored for real, and anyone can independently check that identity without trusting the system that issued it.

**How it works:**

- There's now a real database-backed registry of agents. Register a new agent through the command line and the identity service generates it a fresh cryptographic keypair, builds it a standard identity document (a "DID document," at its own web address), issues it a signed digital credential, and stores all of that — not in a temporary in-memory demo anymore, in Postgres.
- The private half of that keypair — the part that must never leak — now goes through a small, swappable "key vault" interface rather than being passed around as a raw value in code. Today that interface is backed by an in-memory implementation (still never touches disk), but the interface itself is exactly what a real hardware/cloud key vault (AWS KMS) will plug into later without touching any of the surrounding code. This closes a shortcut that was explicitly flagged as temporary in Phase 0's code.
- `custos verify` is now a real, independent check: given a credential, it fetches the issuer's identity document itself, over the network, and checks the signature — it shares no internal state with whatever service issued the credential in the first place. That's the property that makes a credential actually trustworthy rather than just self-reported.
- Proven end-to-end with an automated test that does the whole thing for real: register an agent through the CLI, independently verify its credential (pass), then tamper with that credential after the fact and confirm verification now correctly rejects it.
- The first real push of this phase's CI run caught a genuine gap: the automated test environment's database started completely empty, and nothing was telling it to set up its tables before the tests ran against it — so every test that touched the database failed. Fixed by adding the missing setup step, verified locally by deliberately recreating that broken condition and confirming the fix resolves it, then pushed as a follow-up commit.

**Why it matters:** This is the difference between "the cryptography works in principle" and "every agent that shows up gets a real, durable, independently-checkable identity." Everything from here — issuing scoped access tokens (Phase 2), revoking a compromised agent in under a second (Phase 3), and proving what an agent did (Phase 4) — depends on agents having exactly this kind of real identity to hang off of.

**Status:** Done, verified locally, pushed, and confirmed green on GitHub's automated checks after the CI fix.

**Next up:** Phase 2 — credentials and the vault: agents stop existing only as identities and start being able to actually _do_ something, safely. The vault will hold real third-party tool credentials (GitHub, Stripe test mode) and hand agents short-lived, scoped access tokens instead of ever giving them the real keys.

---

## 2026-08-22 — Phase 0: Cryptographic identity primitives

**Commits:** `480a97f` — "feat: close Phase 0 knowledge gap - Ed25519, did:web, and one signed VC"; `056fc67` — "fix: use pnpm-compatible SBOM generator in release.yml". Both pushed to `origin/main`.

**What shipped:** The three pieces of cryptography Phase 0 exists to prove out: an agent can generate a digital identity, present it in a standard, machine-readable format, and have a document cryptographically signed and independently checked for authenticity — with a working demonstration of what happens when someone tampers with a signed document (it's caught).

**How it works:**

- An agent's identity starts as a cryptographic keypair — a private half that only the agent (or, later, a secure key vault acting on its behalf) ever uses to sign, and a public half anyone can use to check a signature. This uses the Ed25519 signature scheme, the same family of cryptography used in SSH and modern TLS.
- That public half gets published as a small standard document (a "DID document," did:web being one of the W3C's standard identity formats) at a well-known web address — `/.well-known/did.json` — the same pattern browsers use for TLS certificate validation. The `identity` service now serves one of these.
- On top of that, we can now issue a "Verifiable Credential" — a signed, standardized digital document (think: a digitally-signed ID card) — and hand it to anyone who can independently check, using only the published public key, that it's genuine and untampered. We deliberately used an existing, spec-conformant library for the underlying data-normalization step (the part of the W3C credential spec that's genuinely easy to get subtly wrong in a way that wouldn't show up until much later — see the architecture decision recorded in `docs/adr/0001-vc-proof-format.md`) rather than writing that piece from scratch.
- Every one of these checks is proven with an automated test that tries to break it: tamper with a signed credential and confirm it's rejected, sign with the wrong key and confirm it's rejected, feed in malformed data and confirm the system fails safely instead of crashing.
- Along the way, pushing this was also the first time the automated release pipeline actually ran (nothing had triggered it before). It failed — a tool it used to generate a security/compliance manifest didn't understand how this project manages its packages — and that's now fixed too, so the full pipeline runs clean end to end, not just the parts we'd tested before.

**Why it matters:** This is the actual cryptographic foundation the whole "cryptographic identity for agents" claim rests on — everything in Custos's pitch (revocation, scoped access, audit trails) depends on this working correctly first. It's now proven working end-to-end in code, not just designed on paper. What it unblocks: Phase 1, where this becomes a real per-agent identity service instead of a one-off demonstration.

**Status:** Done, verified locally, pushed, and confirmed green on GitHub's automated checks (lint, type-check, test, build, and release pipeline all passed).

**Next up:** Phase 1 — turn this from "the primitive works" into "every agent gets one": a real identity service that generates a keypair, DID, and signed credential per agent, backed by a proper key vault instead of an in-memory demo key, plus a registry to track which agents exist.

---

## 2026-08-19 — Phase 0: Scaffold

**Commit:** `2159845` — "chore: scaffold monorepo skeleton for Custos" — pushed to `origin/main`.

**What shipped:** The project skeleton. No product features yet — this is the foundation everything else gets built on: repo layout, build tooling, automated testing/CI, and a local development environment. Think of it as pouring the foundation and running utilities before framing the building.

**How it works:**

- The codebase is one repository ("monorepo") containing four backend services (`identity`, `vault`, `revocation`, `audit`) and a set of shared libraries they'll all depend on — a pure crypto/identity core, shared data contracts, a developer-facing SDK, per-tool connectors, logging, and config validation.
- Each of the four services currently does nothing but respond to a health check (`/health`) — they're empty shells proving the wiring works, not yet doing identity or credential logic.
- A local environment (Postgres database + Redis cache) starts with one command via Docker.
- Every push automatically runs linting, type-checking, and tests, and will block a merge if any fail. A weekly automated scan checks for security vulnerabilities in dependencies and leaked secrets.
- A pre-commit check on this machine already blocks obviously broken code before it's even committed.

**Why it matters:** Before writing any identity or security logic, we proved the team (and Claude) can reliably build, test, and ship code end-to-end. This is infrastructure investment, not a customer-facing milestone — nothing here can be demoed to a user yet.

**Status:** Done, verified locally, and pushed. Not yet deployed anywhere — this only runs on a developer machine so far.

**Next up:** Remaining Phase 0 work — cryptographic identity primitives (generating and verifying digital signatures for agents), a basic machine-readable identity document, and issuing/verifying one digital credential. This is the first real building block of "give every agent a cryptographic identity."

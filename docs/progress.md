# Custos — Progress Log

Plain-language record of what has actually been built, how it works, and why it matters — for tracking Custos as a project, not just as code. Updated after every phase completion and every push to `origin`. Newest entry on top.

This is not the technical handover (that's section 0 of `CLAUDE.md`, written for a future Claude session). This is written for a person tracking the state of the startup.

---

## 2026-09-25 — Phase 5 build finished; security gaps found and the fix designed

**Commits:**

- PR #39, on `feat/phase-5-readme`: `328756e`, `938cfd6`, `11b5b02`, `5375562` (plus this log entry).
- PR #40, on `docs/phase-5b-auth-design`: `9f1d271`.

Both are pushed and open, awaiting CI and merge. PR #38 (the SDK) is merged.

**Status:** Every build item in Phase 5 now exists and works. Its final check, a person other than the founder setting Custos up using only the README, is deliberately scheduled after the security work below, because that work changes the steps the README teaches.

**What shipped (PR #39):**

- **A README that takes a stranger from nothing to a revoked agent.** Step by step: install, start the services, register an agent, watch it be refused, grant it one tool, use it, cut it off, and check the signed record of everything that happened. It covers both Mac/Linux and Windows, with a troubleshooting table. Every command in it was actually run against the real system, not just written down.
- **Three real bugs, found by following the README exactly as a stranger would.** Automated tests hadn't caught any of them:
  - **The live dashboard never started.** Its start command pointed at a file that sets the server up but never switches it on.
  - **The one real tool connector, Stripe, had never worked against real Stripe.** Every request went to the wrong web address. The tests talked to a fake Stripe that happened to accept the wrong address.
  - **Every refusal printed a wall of programmer error text**, including the moment the whole demo is built around. It now prints one line, such as `denied: AGENT_REVOKED`.

  Each fix comes with a test that fails if the bug ever returns.

- **The command-line tool now runs on the developer library (SDK).** There's one implementation instead of two copies that could drift apart.

**What was found, and designed (PR #40):**

Walking through the product as a user surfaced two security gaps that matter before anyone uses Custos for real:

1. **Anyone with a copy of an agent's ID file can impersonate the agent.** The system checks that the ID card is genuine, but not that the person holding it is its owner.
2. **The administrative controls have no login.** Anyone who can reach the system could swap a stored tool password or grant themselves access.

The fix is written down as a formal decision record (ADR 0007) and a new phase in the build plan, Phase 5b:

- Each agent will hold its own secret key, and prove it has it whenever it asks for access. A copied ID file becomes useless.
- The company's Custos installation will sign every agent's ID card, like a passport office, so any verifier can confirm which organisation vouched for the agent. It works offline too, which is exactly what the next milestone (trust between two companies) needs.
- Administrators will need to log in, first with API keys, then with certificates (mTLS), then with company single sign-on.

One piece of groundwork was confirmed: Amazon's key-protection service (AWS KMS) supports the exact signature type Custos uses, so production keys can be locked in hardware-backed storage without changing any cryptography.

**Why it matters:** The MVP is fully built and documented. More importantly, this found and planned the fix for the gap a serious customer's security team would have found first. "A copied file lets you impersonate an agent" is the question a CISO asks in the first meeting. Custos will now have a designed, test-backed answer before that meeting happens.

**Next up:** Merge PRs #39 and #40. Then Phase 5b, step 1: a signing key for the identity service that survives restarts, so the upcoming "passport office" signatures stay valid.

---

## 2026-09-24 — Phase 5: the developer SDK

**Commits:** `a351289` (the SDK). Pushed to `origin/feat/phase-5-sdk`, open as PR #38. Not yet merged. Opening the PR is what starts CI, so the automated checks run there. The previous batch (Phase 4 + dashboard, PR #36) is now merged to `main`.

**Status:** Implemented and passing every check locally: lint, type checks, the full test suite, and the end-to-end tests against the real running services. CI results are pending on the PR.

**What this is:** Until now, the only way to use Custos was the command line: type `custos register`, copy an ID, type `custos grant`, and so on. That's fine for a demo but not for a developer building an AI agent, who wants to use Custos from inside their own code. The SDK is that: a small library a developer adds to their project. Registering an agent, giving it access to a tool, using the tool safely, and cutting the agent off each take one line of their own code.

**How it works:**

- A developer points the library at the three Custos services and gets four operations: **register** a new agent, **grant** it access to a tool, **connect** it to that tool and make calls, and **deprovision** it (cut it off everywhere).
- When the agent makes a call, the library gets a 60-second pass from the vault and immediately uses it. The agent never sees the real tool password (the vault uses it on the agent's behalf), and it never holds the pass longer than that one call.
- **A refusal is treated as an answer, not a crash.** If the agent isn't allowed to use a tool, or has been cut off, the developer gets a clear "no" with the reason: not permitted, revoked, or pass expired. This matters for a security product. If a refusal looked like an ordinary error, a developer's code could easily retry it or ignore it and quietly treat a revoked agent as a temporary glitch. As a distinct answer, it has to be handled deliberately.
- **It fails safe.** If the vault's reply is garbled or incomplete, the library refuses to go further rather than guessing. Nothing counts as "allowed" unless the vault clearly said so.
- The build plan named three operations. The fourth, **grant**, was added because Custos refuses access by default (since Phase 4). Without it, a developer using only the library could never get past the first call.

**Proof it works:** An automated test starts the real identity, vault, and revocation services and runs a whole agent lifecycle through the library alone. The new agent is refused before it's granted access, allowed after, still refused on a tool it wasn't granted, and then deprovisioned. Its very next call is refused in well under a second. A second test tampers with an agent's identity document and confirms the vault rejects it.

**Why it matters:** This is the step from "a system the founder can demonstrate" to "a product a developer can build on." Phase 5's goal is that someone who isn't the author can take Custos and make it work unassisted, and the SDK is the thing they'd actually use.

**Next up:** Merge PR #38 once CI is green. Then the last Phase 5 item: a README that gets a stranger from zero to a working agent, including the revocation moment. Tested by having someone other than the author follow it. That completes the MVP.

---

## 2026-09-24 — Phase 4 + dashboard pushed to a feature branch

**Commits:** `d0ed428` (Phase 4 authorization and audit), `51e8709` (live trust dashboard), `1cc8cf6` (docs split + orientation rule + pre-push gate). Pushed to `origin/feat/phase-4-and-5-partial`. Not merged to `main` — CI only runs on pull requests and on pushes to `main`, so opening a PR is what will put this work in front of the automated checks.

**Status:** Implemented and working, confirmed by both automated tests and by hand — literally starting the four real services, registering a real agent, and watching an allowed action succeed and a disallowed one get refused, in real time.

**What this is:** Phases 1–3 gave every agent an identity, took away its permanent keys, and proved a compromised agent can be cut off in under a second. What was still missing: nothing stopped an agent from asking to use _any_ tool it wanted — access was all-or-nothing once an agent proved who it was. Phase 4 adds the missing piece: deciding **what each agent is specifically allowed to do**, and keeping a tamper-evident record of every time it tried.

**How it works:**

- An operator can now grant a specific agent access to a specific tool — one command (`custos grant`), one entry in a simple list. No grant means no access: the system defaults to refusing, not allowing, exactly the posture you'd want from a security product.
- That check happens the moment an agent asks for temporary access to a tool, before it's ever handed a usable pass. An agent that was never granted Stripe access gets refused instantly and clearly — it never even gets close to touching the real tool.
- Every single attempt an agent makes — whether it succeeds or gets refused — is now written to a brand-new fourth service, the audit trail. Each entry records who did it, what they tried to do, what kind of data that tool touches, which rule decided the outcome, and whether it was allowed or denied. It's signed, the same way a revocation notice is signed, so it can't be quietly edited after the fact.
- Recording an action never slows down the actual request — the system fires off the audit entry in the background and moves on immediately, the same "don't wait around" principle that makes revocation fast.
- A new command, `custos audit-log`, pulls that trail for any agent and checks every single entry's signature itself, independently — the same "don't just trust the database, verify it" principle already used to check an agent's identity.
- **A genuine bug was caught by testing this against the real running services, not just inside the automated test suite.** The audit service's signing key was being regenerated every time the service restarted — completely normal for how every other service here already works — but that meant every historical audit entry would permanently stop verifying the moment the service restarted, which would have quietly broken the entire promise of the audit trail. The fix (borrowed directly from how the existing revocation notices already solve the identical problem) was to sign each entry fresh every time it's read back, rather than once when it's first written. Re-tested by hand — starting the service fresh with a brand-new key — to confirm old entries still check out.

**Why it matters:** This is the difference between "we can revoke a bad agent" and "we can prove, to someone who doesn't trust us, exactly what every agent was allowed to do and what it actually did." That second property is the whole basis of the compliance angle Custos is exploring — proving which agent, acting under whose authority, touched what — and it's the last piece the MVP core needed before Phase 5 turns this into something a stranger could pick up and run themselves.

**Next up:** Phase 5 — the developer-facing polish pass: a minimal SDK, a clean CLI, a visual moment for the revocation demo, and a README good enough that someone who isn't the author can complete the whole flow unassisted.

---

## 2026-09-10 — Phase 3: Revocation engine (shipped)

**Commits:** `b3b388f` — "feat: Phase 3 revocation engine - status list, signed tombstone push, deprovision"; two follow-up commits fixed CI issues unrelated to the feature itself (a known-vulnerable indirect dependency, and a third-party GitHub Action that had quietly moved to a newer, incompatible major version). Merged to `origin/main` via PR #28, and every automated check is green.

**Status:** Shipped and confirmed working by the real automated build, not just on one machine.

**What this is:** This is the headline feature — the reason Custos exists as a company. Phase 1 gave every agent a real identity. Phase 2 let an agent borrow temporary access to a tool instead of holding a permanent key. Phase 3 is what happens when an agent goes bad: one command, and that agent is locked out of every tool it was touching, in well under a second — and provably so, not just "trust us."

**How it works:**

- There's now a real "revocation service" — a fourth backend service alongside identity, vault, and (later) audit. When an agent is registered, this new service hands it a reserved slot in a public list that says, for every agent ever issued, whether it's still allowed to operate. That list is published as a small, digitally signed document anyone can fetch and check for themselves — a genuinely independent, third-party-verifiable record of who's been cut off, not just an internal database flag.
- Running `custos deprovision <agent-id>` does two things at once: it flips that agent's entry in the public list, and it immediately broadcasts a signed "this agent is revoked" notice directly to the vault — the same "push it out, don't wait to be asked" pattern used for a fire alarm rather than a manual headcount.
- The vault keeps a live, in-memory answer to "is this agent currently allowed?" — checked in microseconds on every single tool call, with no database lookup and no waiting. The moment a revocation notice arrives, that answer flips instantly for every call after it, including ones using a temporary access pass the agent obtained just seconds earlier.
- Each tool connector (Stripe, and the two internal stand-ins used for testing) also independently refuses a revoked agent on its own — so even a request that somehow bypassed the vault's own check still gets refused at the tool itself. Belt and suspenders.
- If the vault ever loses touch with the revocation service for too long, it doesn't quietly assume everything's fine — it starts refusing calls until it's heard from the control plane recently enough to trust its own answer. An outage fails safe, not open.
- Proven with a real automated test, not just described: an agent gets short-lived access to three different tools, actually uses all three successfully, then one `deprovision` command is issued — and all three tools reject that same agent, measured at well under one second, with the individual tool connectors also independently confirming the refusal. That's the literal thing this phase was built to demonstrate, running in an automated check every time the code changes.
- Along the way, the revocation list format itself needed a real decision: the original plan named a 2021 draft spec that has since been finalized and renamed by the W3C. Custos now implements the current, finished standard rather than the superseded draft — the sensible call for a brand-new product with no existing integrations to break by doing so.

**Why it matters:** This is the moment "trust layer for AI agents" stops being a claim and becomes something you can watch happen. It's also the clearest kind of demo there is — plug in an agent, watch it work, revoke it, watch it instantly stop. What it unblocks: Phase 4, which decides _what_ an agent is allowed to do in the first place (not just whether it exists) and builds the tamper-evident log of everything every agent has done.

**Next up:** Phase 4: fine-grained permissions per agent, and a signed audit trail.

---

## 2026-09-06 — Phase 2: Credentials & vault (dispossession)

**Commits:** `91f45f5` — "feat: Phase 2 credentials and vault - scoped tokens, dispossessed agents"; `a298905` — handover docs; `83a5161` — test-suite hardening; `20126a4` — the CI fix described below. All pushed to `origin/main`, and CI is green.

**What shipped:** Phase 1 gave every agent a real, checkable identity. Phase 2 is the step that makes Custos actually useful without being dangerous: agents can now ask to use a real third-party tool (Stripe, in test mode) and two stand-in tools, and get temporary, narrowly-scoped access — without the agent ever holding the real key to that tool. That's the core promise of the product: agents are dispossessed of the credentials they use.

**How it works:**

- There's now a real vault service. An operator stores a tool's real credential with it once (say, a Stripe test-mode key) — the vault encrypts it before saving it to the database, so even someone with direct database access can't read it back out. The plaintext key exists only briefly, in memory, at the exact moment it's needed.
- When a registered agent wants to use a tool, it doesn't get that stored key. Instead, it asks the vault for permission, presenting its own identity credential from Phase 1. The vault independently re-checks that credential is genuine (the same "don't trust, verify" pattern as Phase 1's `custos verify`), and if everything checks out, hands back a temporary access pass — good for 60 seconds, and usable for exactly one tool and one action, nothing broader.
- The agent uses that temporary pass to actually make the call. The vault checks the pass is genuine and not expired (all of that happens instantly, without touching the database), then — and only then — decrypts the real credential, makes the call to the tool on the agent's behalf, and hands back the result. The agent still never sees the real key.
- After 60 seconds, that pass simply stops working — proven with an automated test that requests a pass, uses it successfully, lets it expire, confirms the same pass is now rejected, and shows a freshly-requested pass works again. No real-time waiting was needed to prove this: time is simulated in the test, the same way a stopwatch can be fast-forwarded.
- Three tools are wired up: a real one (Stripe, test/sandbox mode — listing test customers) and two realistic stand-ins (a fake Slack and a fake internal database) that exist to prove the pattern isn't a one-off special case for Stripe.
- Beyond the automated tests, this was also smoke-tested for real: the actual identity and vault services were started as real processes, a real agent was registered through the command line, a tool credential was seeded into the vault, and a tool call was made through the full real stack — not just inside the test runner.
- Getting the automated build green again took a real fix, and the bug is worth recording because it was well disguised. The build had been failing for several commits — including one that changed nothing but documentation, which was the clue that the problem was not in the new code. Our build tool passes only an explicitly-approved list of settings down to the test step, and the database address was not on that list. So the step that prepares the database saw the correct address and worked, while the tests that follow silently fell back to a built-in default address. On a developer machine that default happens to be right, so everything passed locally; on the build server nothing is listening there, so every test that touched the database failed. The fix was to declare that setting explicitly. We confirmed it rather than assuming: pointing the tests at a deliberately dead address now fails exactly the tests that were failing on the server, where before the fix it wrongly passed.

**Why it matters:** This is the first moment Custos does something a company would actually deploy for a reason beyond "prove the crypto works" — an AI agent can now be given narrow, temporary access to a real paid tool instead of a permanent API key that, if leaked or misused, keeps working forever. What it unblocks: Phase 3, revocation — the headline demo of the whole project, where a compromised agent's access to every tool it's touching gets cut within about a second.

**Status:** Done. Verified locally (automated tests, full lint/typecheck/build, and a manual live run), pushed, and **confirmed green on GitHub's automated checks** as of `20126a4`.

**Next up:** Phase 3 — the revocation engine, the reason this project exists. One `custos deprovision` command should cut an actively-misbehaving agent off from every tool it's using, visibly, in about a second.

---

## 2026-08-24 — Phase 1: Identity core

**Commits:** `b8034fc` — "feat: Phase 1 identity core - per-agent registry, KMS-shaped signing, CLI"; `8097daf` — "fix: run pending migrations before the test job in CI". Both pushed to `origin/main`.

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

**Commits:** `e4d9c7b` — "feat: close Phase 0 knowledge gap - Ed25519, did:web, and one signed VC"; `5ffce60` — "fix: use pnpm-compatible SBOM generator in release.yml". Both pushed to `origin/main`.

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

**Commit:** `6780167` — "chore: scaffold monorepo skeleton for Custos" — pushed to `origin/main`.

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

# Custos — Build Plan

**Visual companion:** `docs/build-plan.drawio` (same content, diagram form)
**Scope authority:** this file. The PRD (`docs/prd.md`) defines features and requirements; this file defines phase order and completion criteria.

---

## Current phase

> **CURRENT: Phase 5b — Auth hardening** (in progress). Phase 5 is built; its DONE check (non-author README run) follows 5b.

Update this line as phases complete. Claude Code must not build ahead of it.

---

## Principles

Build strictly in order. Do not start a phase until the previous phase's DONE criteria pass.

Every phase ends with something that **runs** — not something "in progress with nothing to show." If a phase cannot be demonstrated by executing a command and observing the result, it is not finished.

Phases 0–5 constitute the MVP: one agent's complete, safe lifecycle. Phase 6 is post-MVP and is built _on_ the MVP core, not alongside it.

---

## Phase 0 — Foundations & skeleton

Close the one genuine knowledge gap, then stand up production-grade scaffolding.

- Ed25519 keypair generation, signing, verification
- Build one `did:web` DID document, served at `/.well-known/did.json`
- Issue and verify one W3C Verifiable Credential
- Monorepo skeleton per CLAUDE.md structure, Docker Compose dev environment, CI running lint + typecheck + test

**DONE =** sign a message, verify it, tamper with it and watch verification fail; `pnpm dev` brings up the stack; CI green on push.

---

## Phase 1 — Identity core

**MILESTONE: crypto works**

- Identity service: keypair → DID → signed VC per agent
- Verifier that independently checks credential authenticity
- Minimal agent registry with versioned migrations

**DONE =** register an agent via CLI and independently verify its credential; a tampered credential is rejected, proven by test.

---

## Phase 2 — Credentials & vault (dispossession)

- Vault stores real tool credentials server-side
- Short-lived scoped token issuance (60s default) to verified agents
- Two or three tool connectors, at least one real (GitHub or Stripe test mode)
- **Agents never receive raw tool keys** — this is the core security property

**DONE =** an agent requests tool access, receives a 60s scoped token, makes a successful call, the token expires, and the next call requires a fresh request.

---

## Phase 3 — Revocation engine ★

**MILESTONE: the "it's real" demo**

This is the reason the project exists. Give it the most attention.

- Credential status flip (Bitstring Status List v1.0 — the W3C Recommendation that superseded the StatusList2021 draft; see `docs/adr/0005-revocation-architecture.md`)
- Signed revocation tombstone broadcast to registered tool adapters
- Adapters honour revocation

**DONE =** an agent actively calling three tools; one `custos deprovision` command; all three calls fail within roughly one second. Visibly fast and unambiguous.

---

## Phase 4 — Authorization & audit

- Policy engine: simple allowlists per agent × tool (not full OPA/Rego)
- Signed, append-only audit record per action, carrying agent identity, authority chain, data categories, policy applied, decision

**DONE =** agent A may call GitHub but not Stripe, enforced; pull a verifiable log of every action every agent took.

---

## Phase 5 — Developer surface & clean demo ★

**MILESTONE: MVP complete**

- Minimal SDK: `register()`, `connect(tool)`, `deprovision()`
- Clean CLI
- Strong terminal output, or a minimal dashboard, that makes the revocation moment visual
- README that gets a stranger from zero to working

**DONE =** someone who is not the author completes the full flow using only the README.

Sequencing: Phase 5's DONE check (the non-author README run) happens **after** Phase 5b. Phase 5b changes the registration flow the README teaches, so validating the README first would waste the tester's run on a flow about to change.

---

## Phase 5b — Auth hardening

Added 2026-09-25 after a security review found two gaps: an agent credential is a bearer credential (a copied `agent.json` is enough to act as the agent), and the control-plane endpoints have no operator authentication. Design: `docs/adr/0007-agent-key-custody-and-proof-of-possession.md` (agents) and ADR 0008 (operators, written when that part starts).

In order:

1. **Stable issuer key.** `KeyProvider` can use an existing key by ID; an AWS KMS implementation (Ed25519); a dev implementation keyed from an env var, with no default.
2. **Agent-held keys + issuer-signed credentials.** The agent generates its own keypair and registration proves possession of it. The identity service signs credentials as issuer, with the agent's public key embedded. Every vault read of agent identity moves from `issuer` to `credentialSubject.id`.
3. **Proof of possession on `POST /tokens`.** A DPoP-pattern signature over method, URL, timestamp, unique ID and credential hash; bounded skew; a replay cache.
4. **Operator authentication**, behind one `OperatorAuthenticator` interface, on `/credentials`, `/policies`, and the revocation service's `/revocations`:
   - scoped API keys first: SHA-256 hashed at rest, constant-time compare, shown once, expiring, every write audited with the operator's identity;
   - then mTLS;
   - then SSO (OIDC).
5. SDK, CLI and README updated to the new flow; threat model documented in the repo.

**DONE =** all of the following, each proven in CI:

- a copied credential without its private key is refused at `/tokens`;
- a replayed proof is refused;
- an identity service restart does not invalidate previously issued credentials;
- a revoked agent is still denied, keyed on the subject, not the issuer;
- every control-plane endpoint rejects unauthenticated, wrongly-scoped, and expired operator credentials with one uniform error;
- mTLS rejects expired, wrong-CA, self-signed, and mismatched-SAN certificates;
- SSO rejects tokens with a bad signature, issuer, audience or nonce, and expired ones;
- the full `pnpm test:e2e` lifecycle passes on the new flow.

---

## Phase 6 — Cross-org federation (post-MVP) ★

**MILESTONE: the "it's big" demo**

Two machines, two independent trust domains. This is the MVP core built twice with a trust bridge between them — it can only follow a working core.

- Separate DID documents and signing keys per domain
- Trust anchor configuration
- Agent B verifies Agent A from A's signed credential and resolved DID alone
- Cross-org revocation both sides honour

**DONE =** machine A's server is switched off entirely; B still verifies A's agent from the credential alone; revoke A; B correctly rejects.

The offline verification is the entire point. If B needs to call A's server, it is a distributed single-org system, not federation.

---

## Later (demand-pulled, not scheduled)

Sidecar and hot/cold split deployment, structured data proxy, content inspection, egress and eBPF enforcement, hosted and TEE deployment modes, open-source release and protocol publication.

Interfaces should accommodate these. Implementations wait for demand.

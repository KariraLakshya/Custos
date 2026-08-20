# Custos — Build Plan

**Visual companion:** `docs/build-plan.drawio` (same content, diagram form)
**Scope authority:** this file. The PRD (`docs/prd.md`) defines features and requirements; this file defines phase order and completion criteria.

---

## Current phase

> **CURRENT: Phase 1 — Identity core**

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

- Credential status flip (VC Status List 2021)
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

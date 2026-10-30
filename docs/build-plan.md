# Custos — Build Plan

**Visual companion:** `docs/build-plan.drawio` (same content, diagram form)
**Scope authority:** this file. The PRD (`docs/prd.md`) defines features and requirements; this file defines phase order and completion criteria.

---

## Current phase

> **CURRENT: Phase 7 — Packaging (ADR 0018, 2026-10-30), on branch `feat/packaging`. Phases 7–11 below are the founder's 2026-10-28 order.** Previously: after Phase 6 — the audit log as a sealed ledger (ADR 0017). **Parts 1 and 2a merged (PRs #111, #112, 2026-10-27/28); part 2b (S3 Object Lock) merged 2026-10-29 (PR #117); its real-AWS proof is **deferred to launch** by the founder (2026-10-28): the separate Postgres seal server stays the outside store until then, and switching is setting `AUDIT_SEAL_STORE_URL=s3://<bucket>` plus that proof. Next, decided 2026-10-28: packaging (container images), then delegation provenance, then sidecar and eBPF; being written up as phases with an ADR on branch `feat/packaging`. Before that: revocation and publisher keys in KMS (ADR 0016), merged 2026-10-25 (PR #110). Before that: Phase 6 — Cross-org federation, closed 2026-10-22 (all five steps on `main`). Started 2026-10-16 by the founder's decision, _before_ Phase 5's DONE check.** No further phase is planned yet: the next piece of work is chosen with the founder. Deliberate deviation from "do not start a phase until the previous one's DONE criteria pass": no non-author tester could be found. Phase 5's DONE check (the non-author README run, brief in `docs/readme-test.md`) stays open and is still owed. ADR 0014 is Accepted and all five steps are built (the foreign-agent verifier, A's merge of the published list, the publisher, B's gate and status cache in `packages/federation`, and the two-stack end-to-end run). ADR 0014's e2e version of the DONE criterion passes in `apps/admin/src/federation.e2e.test.ts`, on one machine and one Postgres server: A's services are stopped and A's database refuses connections, B still verifies, and a revocation published through the publisher is refused by B within one poll. The criterion below says "machine A's server is switched off entirely" and the milestone says "two machines", and the founder accepted this one-machine run as closing Phase 6 on 2026-10-22. Next: the founder-approved cross-company dashboard panel (beyond this plan). Previously: Phase 5 — DONE check (the non-author README run). Phase 5b (auth hardening) is complete: steps 1–5 done, every DONE criterion below proven in CI, threat model in `docs/threat-model.md`. Phase 6 follows the README run.

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
4. **Control-plane authentication** (ADR 0008), behind one `ControlPlaneAuthenticator` interface that yields a `Principal` (operator or service) with scopes:
   - **operators** on vault `/credentials` and `/policies`, revocation `/revocations`, and — decided 2026-10-01 — identity `/agents` (registering an agent needs operator approval);
   - **services** on audit `/records` and revocation `/agents` — decided 2026-10-01 (closes forged-audit-record and status-slot-exhaustion holes);
   - scoped API keys first: SHA-256 hashed at rest, constant-time compare, shown once, expiring, created only by a local DB-access command, every write audited with its principal;
   - then mTLS;
   - then SSO (OIDC).
5. SDK, CLI and README updated to the new flow; threat model documented in the repo.

**DONE =** all of the following, each proven in CI:

- a copied credential without its private key is refused at `/tokens`;
- a replayed proof is refused;
- an identity service restart does not invalidate previously issued credentials;
- a revoked agent is still denied, keyed on the subject, not the issuer;
- every control-plane endpoint rejects unauthenticated, wrongly-scoped, and expired operator credentials with one uniform error;
- an agent can't be registered without an operator key with `agents:register`;
- an audit record can't be inserted without a service key — a forged record is refused, not signed;
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

## After Phase 6 — Revocation and publisher keys in KMS (ADR 0016)

Chosen by the founder on 2026-10-25 as the next work: the blocker ADR 0014 named before the publisher is used for real.

- The KMS key provider moves out of `services/identity` into a shared package
- `services/revocation` signs with an AWS KMS key when configured (`local` stays the default)
- `custos-admin publish-status` signs with the same KMS key
- The open status-list route cannot be used to exhaust KMS signing

**DONE =** against real AWS KMS, the revocation service boots on a KMS key, publishes it in its DID document, and its tombstones and status list verify against that document; the publisher, configured with the same key, publishes a list a foreign verifier accepts; a KMS failure during a revocation leaves the agent revoked, and in the publisher writes nothing and is retried; repeated anonymous status-list requests cost at most one signature per reuse window. Each proven by a test.

---

## After Phase 6 — The audit log as a sealed ledger (ADR 0017)

Chosen by the founder on 2026-10-26: the audit trail is the evidence a DPDP auditor would be shown. Two pull requests, merged in order.

- Part 1: a stable audit key (`local` or KMS); each entry linked to the one before by a hash; the head signed periodically ("seals"); the reporting service recorded in each entry; a verifier in `packages/core` used by `custos audit-log`
- Part 2a (founder, 2026-10-27): every seal also copied to a separate Postgres server the audit service can only add to, and checked by the verifier
- Part 2b: the same copy in S3 Object Lock, which nobody can delete during retention (built 2026-10-28; the real-AWS proof below is deferred to launch by the founder, 2026-10-28)

**DONE =** each proven by a test: an edited, reordered or deleted middle entry is detected; a log rebuilt and re-sealed with the same key is reported as `DIVERGED` against a seal the verifier already holds; concurrent appends never fork the chain; appends make no KMS call; the reporter in each entry is the authenticated caller (part 1, done). Part 2a: deleting the newest sealed entries **and** the database's copy of their seal is detected from the seal store (`TRUNCATED`); a log rebuilt and re-sealed with the same key, with the forged seal copied through the service's own role, is reported `DIVERGED`; the service's role cannot update, delete, truncate, drop or disable the triggers of the copies; an unreachable seal store blocks nothing and is caught up later, and the verifier fails closed while it is down. Part 2b: against real AWS, seals are written to an Object Lock bucket and cannot be overwritten or deleted.

---

## Forward phases (ADR 0018)

Added 2026-10-30 from the founder's decision of 2026-10-28 (ADR 0018). Built in this order. Each phase opens with its own ADR for the consequential choices it makes; the DONE lines below are the scope. "Not in this phase" is as binding as the DONE line.

## Phase 7 — Packaging

Custos runs from container images, with no source checkout and no Node on the host.

- One image per service (identity, vault, revocation, audit), the dashboard, and a one-shot migration image, built from the monorepo
- A Compose profile that brings the stack up from those images only, next to the existing `mtls` and `sso` profiles; `pnpm dev` and `pnpm demo` are unchanged
- A lifecycle check that drives the CLI against the running image stack (the existing e2e tests build services in-process and cannot do this)
- Image design (base image, pruning the monorepo per image, user, pinning) in its own ADR with the first image

**DONE =** each proven in CI: every image builds; the stack comes up from the images alone (no source mount, no host Node) and passes the README lifecycle (register, grant, allowed, other tool denied, revoke, refused); an image started without a required secret (for example `AUDIT_SIGNING_SEED`) refuses to boot; no seed, key file, `.env` or `infra/mtls/certs` content is in any image layer; every image runs as a non-root user; base images are pinned by digest.

**Not in this phase:** Kubernetes manifests, the sidecar, publishing images to a registry (unless the founder decides otherwise, ADR 0018 open question 1), multi-architecture builds, a production hardening guide.

## Phase 8 — Delegation provenance

Every audit record proves which agent acted, under whose authority, through which other agents (CLAUDE.md §10, DPDP).

- An agent can delegate to another agent a subset of what it may do; each link in the chain is signed by the delegator
- The vault checks the whole chain on every token request, locally (no control-plane call on the hot path)
- The audit record carries the authority chain, the declared data categories of the tool, the policy applied and the decision, inside the sealed ledger (ADR 0017)

**DONE =** each proven in CI: an agent acting for a human through one sub-agent gets a token, and its audit record carries the full chain, verifiable by `custos audit-log`; a chain with a forged, unsigned or expired link is refused; a sub-agent asking for a tool or action its delegator was not granted is refused; revoking any link refuses every agent below it within the revocation bound; the chain is checked without any network call.

**Not in this phase:** delegation across companies (federation chains), classifying data by inspecting it (categories are declared per tool), a DPDP export format, the sidecar.

## Phase 9 — Sidecar

Agent traffic to tools passes through a Custos process next to the agent, which holds the token flow so the agent never does.

- A sidecar process sharing the agent's network namespace; the agent calls the sidecar, the sidecar gets the scoped token and calls the tool
- The hot path in the sidecar: local credential check, cached policy and revocation state pushed from the control plane

**DONE =** each proven in CI under Compose (agent and sidecar in one network namespace, since Kubernetes comes later): an agent with no credential of its own completes a tool call through the sidecar; a revoked agent is refused by the sidecar within the revocation bound; the sidecar keeps allowing and denying correctly with the control plane stopped, until its cache TTL, then fails closed; the agent cannot read the sidecar's token or key.

**Not in this phase:** Kubernetes injection, blocking an agent that bypasses the sidecar (Phase 10), the data proxy or content inspection.

## Phase 10 — eBPF egress enforcement

An agent cannot reach a tool except through its sidecar, enforced in the Linux kernel.

- Entry precondition: an ADR choosing the language and loader for the eBPF program (not TypeScript; CLAUDE.md §5 "Rust … not now" is revisited there)
- Linux only; proven on a CI Linux runner, since the development machine is Windows

**DONE =** each proven in CI on Linux: a process assigned to an agent cannot open a connection to a tool host directly, and the attempt is refused and audited; the same call through the sidecar succeeds; if the enforcement program is not loaded, the sidecar refuses to serve that agent (fail closed).

**Not in this phase:** a Kubernetes DaemonSet, non-Linux hosts, content inspection, enforcement of anything other than egress.

## Phase 11 — Kubernetes

The Phase 7 images, Phase 9 sidecar and Phase 10 enforcer, deployed on Kubernetes.

- Manifests (format chosen in the phase's ADR); the sidecar added to agent pods; the enforcer as a DaemonSet
- Proven on a throwaway cluster in CI (for example kind)

**DONE =** each proven in CI: the stack deploys from the Phase 7 images and passes the README lifecycle; an agent pod gets its sidecar and cannot reach a tool directly; secrets come from Kubernetes Secrets, never ConfigMaps or images; every pod runs non-root with a read-only root filesystem.

**Not in this phase:** a service mesh, multi-region, autoscaling, a managed-cloud deployment, edge verifiers.

---

## Later (demand-pulled, not scheduled)

Hot/cold split deployment beyond the sidecar, structured data proxy, content inspection, hosted and TEE deployment modes, protocol publication.

Interfaces should accommodate these. Implementations wait for demand.

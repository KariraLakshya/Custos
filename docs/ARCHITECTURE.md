# Custos — Architecture

**Status:** Phases 0–5 built; Phase 5b (auth hardening) complete. Phase 5's non-author README run is next. See `docs/state.md` for the live handover and `docs/threat-model.md` for what the security controls do and don't cover.

This file answers _why_ the system is shaped the way it is. `docs/build-plan.md` is authority on _what's next_. `docs/prd.pdf` is authority on _what and why, product-side_. `docs/adr/` carries the full reasoning behind every decision summarized here — this file is the map, not the territory.

---

## 1. What's in the system?

```
apps/cli, apps/sdk (agent-side)              apps/dashboard (read-only monitor)
        │                                              │
        ▼                                              ▼
services/vault  ◄──────────────────────►  services/identity
  (hot path: /tokens, /call)                (DID + VC issuance, agent registry)
        │                    │
        │ revocation cache   │ audit events (fire-and-forget)
        ▼                    ▼
services/revocation      services/audit
  (bitstring status list,   (append-only log,
   signed tombstone push)    signs fresh at read time)
        │
        ▼
packages/connectors (Stripe / mock-slack / mock-database adapters)
        │
        ▼
   real tool APIs
```

Everything above sits on `packages/core` (pure crypto/DID/VC/token primitives, no I/O) and `packages/contracts` (shared Zod schemas + error taxonomy — the common vocabulary every service speaks).

This is the **current, implemented** shape: four standalone Fastify services talking to each other over HTTP with signed, independently-verifiable artifacts, each with its own Postgres and its own ephemeral `did:web` signing identity. It is not yet the **target** deployment shape described in the Notion architecture page and `docs/build-plan.md`'s "Later" section — sidecar-per-agent-pod, edge verifier on Cloudflare Workers, egress NetworkPolicy, eBPF. Those are demand-pulled, post-MVP, and the current services are built so that shape can be dropped in later without changing the invariants below (see §7).

## 2. Who's responsible for what?

| Component             | Owns                                                                                                                                                                            | Does not own                                                                                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/core`       | Crypto, DID docs, VC issue/verify, scoped-token issue/verify. Pure — no I/O, no network, no clock reads outside an injected dependency.                                         | Any decision about _who_ gets a credential or token — that's the services calling it.                                                           |
| `packages/contracts`  | Shared Zod schemas, types, error taxonomy.                                                                                                                                      | Business logic.                                                                                                                                 |
| `packages/connectors` | The `Connector` interface, concrete tool adapters, static `dataCategories` per adapter, `createRevocationGuard()`.                                                              | Deciding whether a call is authorized — that's already decided by the time a connector runs.                                                    |
| `services/identity`   | "Who is this agent" — keypair → DID → signed VC, agent registry.                                                                                                                | Revocation status (calls `services/revocation` for status-list index allocation at registration; registration fails closed if that call fails). |
| `services/vault`      | Dispossession and the hot path: encrypted tool-credential storage, 60s scoped-token issuance, `/call` enforcement, authorization check at issuance, in-memory revocation cache. | Deciding _what_ an agent is allowed to do long-term — that's `agent_policies`, checked once, not re-derived here.                               |
| `services/revocation` | Bitstring Status List (the durable, publicly verifiable record), signed tombstone push (the fast path), status-list index allocation.                                           | Enforcement — it broadcasts and publishes; `services/vault` and the connectors are the ones that actually deny a call.                          |
| `services/audit`      | Append-only action log; signs every record fresh at read time so a signing-key rotation never orphans history.                                                                  | Real-time enforcement — audit is asynchronous and non-blocking by design.                                                                       |
| `apps/cli`            | `register`, `verify`, `use`, `deprovision`, `grant`, `audit-log` — each independently re-verifies rather than trusting a service's say-so.                                      | —                                                                                                                                               |
| `apps/dashboard`      | A live read of `/records` and `/revocations`, polled every 1.5s. Explicitly labeled a monitoring view.                                                                          | Verification. It performs no client-side signature check — the footer says so and points at `custos audit-log`.                                 |

## 3. Why is it built this way?

The load-bearing decisions, in full in `docs/adr/`:

- **DECISION:** VC proof format is JSON-LD Data Integrity via the Digital Bazaar library stack, not a hand-rolled URDNA2015 canonicalizer or VC-JWT. **REASON:** a canonicalizer bug fails silently — two credentials that should differ could canonicalize identically. **TRADE-OFF ACCEPTED:** nine dependencies in `packages/core`, and every credential field must be defined by a loaded `@context`. (ADR 0001)
- **DECISION:** Signing goes through an injected KMS-shaped `signer`, never a raw secret key, from Phase 1 onward. **REASON:** a plaintext-key-store-meant-to-migrate-later makes the migration window itself a vulnerability. **TRADE-OFF ACCEPTED:** none real — `jsonld-signatures` already supports this shape natively. (ADR 0002)
- **DECISION:** Scoped tokens are a custom compact `base64url(claims).base64url(sig)` Ed25519 format, not JWT. **REASON:** a JWT library buys header/algorithm negotiation we don't need and don't want (`alg: none`, algorithm confusion) for one issuer and one algorithm. **TRADE-OFF ACCEPTED:** the format isn't JWT-compatible with anything outside Custos; a future second verifier needs its own out-of-band key distribution. (ADR 0003)
- **DECISION:** Vault-held tool credentials are encrypted at rest with XChaCha20-Poly1305 behind a KMS-shaped `SecretCipher`, keyed by one `VAULT_MASTER_KEY`. **REASON:** a tool credential leak is strictly worse than a signing-key leak — it's directly usable against the real API. **TRADE-OFF ACCEPTED:** one symmetric key for all stored credentials today (no per-tool keys or rotation) — losing it makes every credential unrecoverable by design (AEAD, no key recovery). (ADR 0004)
- **DECISION:** Revocation is Bitstring Status List v1.0 (not the superseded StatusList2021 draft CLAUDE.md originally named), published _and_ pushed as a signed tombstone — not either alone. **REASON:** the status list alone can't be fast (hot path forbids a network call); a push alone has no durable, independently-checkable record. **TRADE-OFF ACCEPTED:** a vault that's never synced starts stale and denies everything — deliberate fail-closed, not a bug. (ADR 0005)
- **DECISION:** Authorization is checked once, at token issuance (cold path), not re-checked on every `/call`. Audit records are signed fresh at _read_ time, not stored pre-signed. **REASON:** checking an allowlist on every hot-path call would mean either a forbidden DB hit or reimplementing revocation's whole cache-and-push machinery for a feature that's explicitly not meant to be full OPA/Rego; a pre-signed record permanently breaks verification the moment an ephemeral signing key rotates (found by manual smoke test, not by design). **TRADE-OFF ACCEPTED:** one extra signing operation per row on every audit read; no revoke-single-grant endpoint yet, only whole-agent deprovision. (ADR 0006)
- **DECISION:** TypeScript over Python, Postgres+Redis from day one (not SQLite/in-memory), OpenTelemetry from the first service, results-as-values (not exceptions) on every verification path, no Rust in the MVP. **REASON, respectively:** the DID/VC library ecosystem is materially stronger in JS; persistence semantics are expensive to port later and the revocation cache's short TTL is a security mechanism, not a nicety; tracing added after the fact is miserable and half-wrong; an exception can be silently swallowed by an unrelated `try/catch`, a result type can't be; learning Rust, DIDs, and VCs simultaneously produces worse code in all three. (`docs/adr/` tech-stack rationale)

## 4. What's allowed to touch what?

```
apps/cli, apps/sdk, apps/dashboard
        │  (HTTP only, signed/verifiable artifacts — never a shared DB)
        ▼
services/* (identity, vault, revocation, audit)
        │  (each imports packages/*, never another service's internals)
        ▼
packages/connectors, packages/contracts
        │
        ▼
packages/core   ← everything depends on this; it depends on nothing
```

Banned patterns, enforced rather than encouraged:

- **No package reaches into another's internals.** Every package declares explicit `exports`; no deep imports.
- **`packages/core` stays pure.** No network, no database, no reading the system clock except through an injected dependency. This is what keeps the cryptographic logic fully unit-testable.
- **No network call to the control plane on the hot path** (`services/vault`'s `/call`). State arrives by push into an in-memory cache, never by asking on the request path.
- **Agents never hold raw tool credentials.** Any code path that hands an agent a long-lived key is a defect, however convenient in the moment.
- **Private signing keys never touch disk, logs, or version control.** Sign only through the KMS-shaped interface.
- **Services talk to each other over HTTP with independently-verifiable artifacts** (signed VCs, signed tombstones, signed tokens) — never by trusting a shared database row, because the whole point is that a third party who doesn't trust Custos's database can still verify.

## 5. How does data actually move?

**Register:** `apps/cli register` (operator key with `agents:register`) → the agent generates its own keypair and sends its public key with a proof of possession → `services/identity` calls `services/revocation POST /agents` for a status-list index (service-authenticated; registration fails closed if this fails), signs a VC as issuer with the agent's public key embedded → returns DID + VC. The private key never leaves the agent (ADR 0007).

**Grant:** `apps/cli grant` (operator key with `policies:write`) → `services/vault POST /policies` writes an `agent_policies` row (deny-by-default).

**Connect / call (the hot path):** agent → `services/vault POST /tokens` (independently verifies the agent's VC against the one trusted issuer, checks a fresh proof of possession signed with the agent's key, checks `agent_policies` once, issues a 60s scoped token) → agent → `services/vault POST /call` (checks the token signature + the in-memory revocation cache — zero I/O until both pass) → `packages/connectors` adapter → real tool API → fire-and-forget `AuditReporter` → `services/audit POST /records`.

**Revoke:** `apps/cli deprovision` (operator key with `agents:revoke`) → `services/revocation POST /revocations` (flips the status-list bit, signs, pushes a tombstone) → `services/vault`'s in-memory revoked-DID cache updates → the agent's next call, on every tool, is denied within roughly a second (proven by e2e test against three tools).

**Control-plane auth:** every write above needs an operator key (from `custos-admin` or `custos login` via SSO), and service-to-service calls need a service key or an mTLS certificate through Envoy (ADRs 0008–0010). Each write is audited with the principal who made it.

**Audit:** `apps/cli audit-log` → `services/audit GET /records` (signs every row fresh at read time) → CLI independently re-verifies, exits 1 on any failure.

**Monitor:** `apps/dashboard` polls `services/audit GET /records` and `services/revocation GET /revocations` directly from the browser every 1.5s — a live feed, explicitly not a verifier.

## 6. What can never break?

- Private signing keys never touch disk, logs, or version control — sign through the KMS-shaped interface only.
- Agents never hold raw tool credentials.
- Tokens are short-lived and scoped — 60 seconds by default, bound to one tool and action set.
- No network call to the control plane on the hot path. State is pushed, never pulled, on the request path.
- Verification is local and offline-capable — never depends on live issuer reachability.
- Security decisions fail closed, with bounded staleness that is explicit configuration (`REVOCATION_MAX_STALENESS_MS`), never an accident.
- Audit writes are asynchronous and non-blocking — losing audit data is a bug, and audit-induced latency is also a bug.
- Crypto is audited only (`@noble/*`) — nothing hand-rolled, no novel constructions.
- Expiry and revocation checks cannot be disabled by configuration.
- Every security control has a negative test proven in CI — a control nobody has watched fail is a control nobody knows works.
- A new dependency needs a stated justification; prefer a primitive over a convenience wrapper.

## 7. Where does new code belong?

- **New tool integration** → implement the `Connector` interface in `packages/connectors`, add contract tests against a recorded/sandboxed version of the real API, declare `dataCategories`, wire `createRevocationGuard()`. Don't build a one-off path that skips the adapter interface.
- **New credential or token type** → extend `packages/core`'s existing envelope pattern (KMS-shaped injected signer, injected clock, bundled-never-fetched contexts). Reuse the pattern from ADR 0001 rather than re-deriving it.
- **New control-plane service** → only when the workload shape genuinely differs from the existing four (identity is low-traffic/security-critical, vault is steady, revocation is bursty, audit is a write-heavy firehose). Don't add a network hop without an isolation reason — see the scaling-profile rationale in the tech stack doc.
- **Deployment/enforcement hardening** (sidecar, egress NetworkPolicy, eBPF, edge verifier, TEE, content inspection) → explicitly `docs/build-plan.md`'s "Later" section. Interfaces should accommodate these; implementations wait for demand. Do not start them early.
- **Cross-org federation (Phase 6)** → builds _on_ the MVP core, not alongside it. Do not start before Phase 5's SDK and README are done and the current phase line in `docs/build-plan.md` says so.

## 8. When does Claude stop and ask?

- **Before crossing an architecture invariant in §6** — e.g., adding a hot-path network call, handing an agent a raw key, making a revocation/expiry check configurable, hand-rolling crypto instead of using `@noble/*`. Stop before writing the code, name which invariant or ADR it conflicts with, show what it would affect, and propose the smallest change that stays inside the invariant (e.g., "cache + push" instead of "call and wait").
- **Before contradicting an existing ADR.** Don't silently work around one. Either follow the existing decision, or write a new ADR explaining the change and update the files it makes stale — the precedent is ADR 0005 renaming StatusList2021 to Bitstring Status List everywhere it appeared, including `docs/build-plan.md`.
- **Before building ahead of `docs/build-plan.md`'s CURRENT line.** Phases are strictly sequential; a phase isn't finished until its DONE criterion is something you can run and observe, not something "in progress with nothing to show."
- **Before taking an undocumented shortcut.** Record it and why in `docs/state.md`'s "Known issues, debt, and deviations" before considering the phase done — an unrecorded shortcut in a security product is a silent vulnerability, not a saved step.

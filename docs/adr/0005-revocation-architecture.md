# 0005: Revocation architecture — Bitstring Status List, signed tombstone push, and index allocation

## Context

Phase 3 is the reason the project exists (`docs/build-plan.md`): one `custos deprovision` command must cut a compromised agent off from every tool it can reach, in about a second, and that cutoff must be verifiable by a third party who does not trust Custos's own database.

Three decisions here are consequential enough to record.

### 1. Bitstring Status List, not StatusList2021

CLAUDE.md section 5 named "VC Status List 2021." That draft (a W3C Community Group draft, not standards-track) was carried through the W3C process and published as **Bitstring Status List v1.0**, a W3C Recommendation, under a new name and a new set of JSON-LD terms (`BitstringStatusListEntry`/`BitstringStatusListCredential`, `encodedList` as multibase rather than bare base64url). The underlying mechanism — a gzipped bitstring, minimum 131,072 entries (16KB) so list size does not leak how many credentials are actually revoked, one bit per credential — is unchanged between the two.

`@digitalcredentials/credentials-v2-context` (already a `packages/core` dependency, chosen in ADR 0001) bundles the Bitstring Status List terms directly; it does not bundle `StatusList2021Entry`. Implementing the literal 2021 name would mean a new dependency, embedding a VC-1.1-era draft term inside a VC-2.0 credential (the exact class of subtle spec mismatch ADR 0001 chose Digital Bazaar's libraries to avoid), and shipping a superseded name in a brand-new product with zero external verifiers to break.

**Decision:** implement Bitstring Status List v1.0 (`packages/core/src/status/bitstring-status-list.ts`). CLAUDE.md section 5 and `docs/build-plan.md` are updated to say "Bitstring Status List" as part of this change, per CLAUDE.md section 12 ("if something in this file is wrong, outdated, or superseded, say so and update it... rather than working around it").

### 2. Signed tombstone push + status list, not either alone

The status list alone cannot make revocation fast: CLAUDE.md section 3 forbids a control-plane network call on the hot path, so a verifier fetching the list on every call is out. The list alone also has no mechanism to _notify_ anything — it is passive, pulled.

A push alone (broadcast "agent X is revoked" and nothing else) has no durable, independently-checkable record — a third party who missed the broadcast, or who does not trust Custos's word for it, has no way to confirm a revocation happened.

**Decision:** both, each doing a different job.

- **Status list** (`services/revocation`'s `GET /status/revocation`, a signed VC wrapping the bitstring) is the durable, publicly verifiable record — rebuilt from the revocation rows on every request rather than cached, since at this scale it is one indexed query and a derived cache cannot be allowed to drift from the rows that are the actual source of truth.
- **Signed tombstone push** (`POST /revocations` on both the revocation service and every subscriber) is what makes revocation _fast_: the vault keeps an in-memory revoked-DID set, updated by push and checked in microseconds on every `/call` (`services/vault/src/revocation/cache.ts`).
- **Bounded staleness, explicit config.** A vault that has never synced starts stale and denies rather than silently claiming "not revoked" (CLAUDE.md section 3: "fail closed... with bounded staleness... explicit configuration, never an accident"). `REVOCATION_MAX_STALENESS_MS` (default 30s) governs how old the local view may be before the hot path starts denying; a periodic resync (`REVOCATION_RESYNC_INTERVAL_MS`) against `GET /revocations` closes the window if a push is missed.
- **Tombstones are signed and independently verified.** An unauthenticated "revoke this agent" endpoint would be a trivial denial-of-service vector — anyone able to reach a vault could revoke any agent. The revocation service gets its own `did:web` signing identity (the same `KeyProvider` pattern as identity and vault); the vault resolves that DID once and verifies every tombstone against it, failing closed on an unverifiable one.
- **Transport is signed HTTP push behind a `TombstoneBroadcaster` interface** (`services/revocation/src/broadcast.ts`), not a message broker. Multi-instance fan-out is not needed yet (CLAUDE.md section 2: implementations wait for demand); the interface is shaped, the same way `KeyProvider`/`SecretCipher` are, so Redis pub/sub can replace the HTTP implementation later without touching callers.
- **Connectors also enforce revocation locally** (`Connector.call()` now takes `agentId`; `packages/connectors/src/connector.ts` exports a shared `createRevocationGuard()`). The vault's own check is the primary gate, but the build plan's DONE criterion is specifically "adapters honour revocation" — a tool adapter that only trusts the vault's word is not actually honouring anything itself.

### 3. The revocation service owns status list index allocation

Registration (`services/identity`) needs to embed a `credentialStatus` entry — a bit index into the published list — in every credential it issues. That index has to come from whichever service owns the list, i.e. `services/revocation`.

**Decision:** identity calls `POST /agents` on the revocation service during registration, before signing the credential, and fails the registration closed if that call fails (`services/identity/src/agents/status-allocator.ts`). The alternative — identity allocating indexes itself and telling revocation about them later — would let identity issue a credential with no real status list entry if that follow-up notification were ever lost, which is exactly the "agent that can never be revoked" failure this product exists to prevent. It also means revocation's own database never depends on identity being reachable, which matters because revocation is the emergency path.

## Consequences

- Third parties integrating with Custos from here on speak Bitstring Status List, the current standard, not a superseded draft — no forced migration later.
- Revocation is genuinely fast (in-memory check, no network call, and the CLI e2e test at `apps/cli/src/cli.e2e.test.ts` proves three tools are cut off well under one second) while still being independently verifiable by a third party who fetches only `GET /status/revocation` and the revocation service's own DID document — neither requires trusting Custos's database.
- The vault denies everything until its first successful sync with the revocation service. This is deliberate fail-closed behaviour, not a bug: a vault that has never heard from the control plane knows nothing about who is revoked and must not answer "not revoked" on that basis.
- Registration now has a hard dependency on the revocation service being reachable. That is the correct direction to fail in — an agent issued with no status list entry could never be revoked — but it does mean revocation's uptime is now on the critical path for `custos register`, not just for `custos deprovision`.
- The real Stripe connector still has no per-agent credential (one shared vault-held key, per Phase 2's ADR-less scope decision) — its `revoke()` marks the agent revoked locally rather than rotating or deleting anything upstream. Genuine per-agent upstream revocation for Stripe is future work once agents each hold a restricted key.

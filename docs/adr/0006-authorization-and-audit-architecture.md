# 0006: Authorization and audit architecture — allowlist enforcement point, audit record signing, and data categories

## Context

Phase 4's DONE criterion (`docs/build-plan.md`): "agent A may call GitHub but not Stripe, enforced; pull a verifiable log of every action every agent took." Three decisions here are consequential enough to record.

### 1. Policy is enforced at token issuance (cold path), not at `/call` (hot path)

CLAUDE.md section 3 forbids a network or database call on the hot path (`services/vault`'s `/call`) — that path already does zero I/O until after the token and revocation checks pass. Checking a Postgres-backed allowlist on every call would violate that invariant directly; mirroring revocation's in-memory-cache-plus-push pattern to keep it off the hot path would be real infrastructure for a feature the build plan explicitly says should not be full OPA/Rego.

**Decision:** `services/vault/src/tokens/issue.ts` checks `agent_policies` once, at token issuance, after the agent's credential has independently verified — authorization is meaningless against an unauthenticated identity, so it is checked after, not before, that step. A token is already scoped to one tool; once issuance for an ungranted tool is refused, there is nothing further for the hot path to re-check, unlike revocation (a token already in an agent's hand can outlive a revocation event mid-flight, which is why that check _is_ repeated on every call). No revoke-grant endpoint exists yet — not required by this phase's DONE criterion, and speculative before it's needed (CLAUDE.md section 2).

### 2. Audit records are signed at read time, not at write time

The natural first design — sign a record once at `POST /records` and store the signed envelope, the same compact-envelope shape as a scoped token or revocation tombstone — was built, then broken by a manual smoke test against the real built services: this service's signing key is ephemeral (`createLocalKeyProvider()`, regenerated on every process start, the same pattern `services/vault` and `services/revocation` already use for their own signing identities). A record signed once and stored as-is permanently fails to verify after any restart, which defeats the entire point of a "verifiable log" the build plan asks for.

`services/revocation` already solved this exact problem for tombstones: `listTombstones()` never stores a signed tombstone, it re-signs fresh from the raw DB row on every `GET /revocations`, so a key rotation is invisible to a resyncing subscriber. The underlying fact (revoked-or-not, when) is durable; the signature over it is disposable and cheap to regenerate.

**Decision:** `services/audit`'s schema (`db/schema.ts`) stores the unsigned fields of an action outcome, not a pre-signed envelope. `POST /records` (`records/append.ts`) only validates and stores. `GET /records` (`records/list.ts`) signs every row fresh, under whichever key is live at request time — identical in shape to `listTombstones()`. A regression test (`server.test.ts`, "still verifies a pre-existing record after a simulated restart with a new signing key") proves a restart does not orphan history. This also means `POST /records`'s response carries no signed record — nothing consumed it (the vault's `AuditReporter` only checks `response.ok`), so returning one would have been dead weight.

### 3. Data categories are a static per-connector declaration, not per-call classification

CLAUDE.md section 10 requires "the data categories touched" on every audit record, in service of DPDP-style compliance framing. Classifying what a given API response actually _contains_ (PII detection, field-level tagging) is explicitly listed as not-yet-in-scope work (CLAUDE.md section 2: "data proxy or PII classification or OCR").

**Decision:** `Connector` gained a static `dataCategories: readonly string[]` field (`packages/connectors/src/connector.ts`) — a fixed declaration of what kind of data a tool touches at all (e.g. Stripe: `["payment-customer-data"]`), set once per adapter, not computed per call. This satisfies the audit schema's requirement today without building a classification engine; real per-response classification is future work if a later phase needs it.

## Consequences

- An agent's authorization is a durable, queryable fact (`agent_policies`), not a cache — there is no staleness window to reason about for authorization the way there is for revocation, because nothing re-checks it after issuance.
- The audit service's signing key can be rotated or lost (a restart, a redeploy) without invalidating any historical record — the property a "verifiable log" needs to actually be useful over time. The cost is one extra signing operation per row on every `GET /records`, negligible at this scale and consistent with `services/revocation`'s already-accepted tradeoff.
- `dataCategories` answers "what kind of data can this tool touch," not "what data did this specific call return" — sufficient for the DONE criterion and the compliance framing in CLAUDE.md section 10, but a real regulator-facing audit trail will eventually need per-response classification; that is future work, not a Phase 4 gap.
- No hash-chaining between audit records exists yet (each row is independently signed and verified in isolation) — a stronger tamper-evidence property than per-record signing alone, but not required by this phase's DONE criterion and genuinely more infrastructure. Deferred, not overlooked.

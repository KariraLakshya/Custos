# 0014: Cross-org federation — pinned trust anchors and an independent status publisher

**Status:** Accepted 2026-10-17 by the founder (design as written, including decisions (a) and Fix 1 and the production-first freshness window). Steps 1–3 are built (see the implementation notes); Phase 6 started 2026-10-16 before Phase 5's DONE check (see `docs/build-plan.md`).

## Context

Phase 6's DONE criterion: _machine A's server is switched off entirely; B still verifies A's agent from the credential alone; revoke A; B correctly rejects._ "If B needs to call A's server, it is a distributed single-org system, not federation."

Two of our own rules pull against each other here:

- **Verification is local and offline-capable** (CLAUDE.md §3). B must verify with A's services down.
- **Fail closed, bounded staleness** (§3, ADR 0013). B's view of A's revocations ages while A is unreachable, and B cannot tell "A is down" from "A is revoking and B is partitioned from it". Silence is not proof of "nothing changed". No design can both accept A's agents indefinitely and guarantee revocation; a time bound has to be chosen.

Two further facts from the current code (ADR 0013):

- The status list is a signed VC whose `validFrom` is the freshness proof. Today the revocation service rebuilds and signs it **at each request**, so `validFrom` is always "now". A static file does not do that. Served from a plain host, the list's `validFrom` ages and B would fail closed after the staleness bound even though nothing changed.
- "Revoke A" cannot be done by A's serving process if that process is off. The DONE criterion only holds if a revocation can be signed and published without it.

## Decision

### 1. Trust anchors are pinned, not resolved

B holds a configured **trust anchor** per foreign domain, supplied out of band:

- `domain` (a label B uses in logs and audit);
- `credentialIssuerDid` and its **public key** (multibase);
- `statusIssuerDid` and its public key (in Custos the status list is signed by the revocation DID, a different key from the credential issuer; both are pinned);
- `statusListId`: the list's identity, which must equal both the credential's `statusListCredential` and the list VC's `id` (a URL on A's domain, derived from A's revocation DID, as in ADR 0013);
- `statusFetchUrl`: where B actually fetches the list (the independent host). The identity and the fetch address are different things, as `REVOCATION_ISSUER_DID` and `REVOCATION_URL` already are in ADR 0013. **B only ever fetches the configured `statusFetchUrl`, never a URL read from a presented credential;**
- `maxStatusAgeSeconds` (**required, no default in code**; the TTL is explicit configuration);
- `enabled` (the distrust switch, below).

Verification never resolves `did:web` and never calls A. The DID in a credential must equal the anchor's, and the signature must verify under the pinned key. (A rotated key means B updates its anchor; rotation across domains is out of scope here.)

### 2. What A's agent presents

Its existing issuer-signed credential (ADR 0007) plus a proof of possession whose audience is **B's URL** (the existing `buildTokenRequestProof` family, with a new proof type so a proof for the vault cannot be replayed at B and the reverse). B checks, in this order, all locally: size and shape; credential signature under the pinned key; `issuer` equals the anchor; expiry **if the credential has one** (see Consequences); the proof's signature against the key embedded in the credential, audience, skew and replay; `credentialStatus.statusListCredential` equals the anchor's `statusListId` with purpose `revocation`; the bit is clear in B's cached list; the list is fresh. No step reaches A.

### 3. Revocation: an independent publisher

Separate two roles:

| Role                 | Does                                                                                                                                         | Must be up when                                            |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| **Serving**          | Identity, vault, audit: registers and authenticates agents                                                                                   | Agents are in use                                          |
| **Publishing** (new) | Operator-run process holding the status-signing key (via `KeyProvider`); builds and signs the list; writes it to a durable, independent host | A revocation happens, and **continuously, as a heartbeat** |

- The publisher **re-signs on every revocation and on a heartbeat**, because the list's `validFrom` is the only freshness proof. Without the heartbeat, B fails closed on a healthy, unchanged domain.
- **A commits to its own freshness.** Each list carries a signed `validUntil` (VC 2.0; the same idea as a CRL's `nextUpdate`). B denies after `min(validUntil, validFrom + its own maxStatusAgeSeconds)`. Without it, the heartbeat interval (A's choice) and the window (B's choice) could not be reconciled by either side; with it, A's promise is signed and B can only tighten it. The heartbeat must be shorter than `validUntil - validFrom`.
- **The published list is the publisher's own state (decided 2026-10-17, founder: "A is off" includes A's database).** The publisher needs nothing from A's machine, database included. It keeps the last list it signed in its own durable local state, re-verifies it, and to revoke an agent sets that agent's bit (the index comes from the agent's `credentialStatus`, which the operator reads from the agent's credential or from the operator's own records), then re-signs and publishes. It reuses the existing list builder (`services/revocation/src/status`) as a library and never calls the revocation service. The host copy is not trusted as input: if the host's list is missing a bit the publisher's own state has, the publisher publishes its own (bits are never cleared).
- **One source of record, by union (decided 2026-10-17, founder: "Fix 1").** Revocation is permanent, so two copies of the list always merge by taking every bit set in either. Before A's revocation service serves anything after a start, it fetches the published list, verifies it under the publisher's key, and ORs its bits into A's database (index to agent DID through the `agents` table; an index with no known DID is recorded by index). Until that first merge succeeds, A's services answer revocation questions with "unknown" (fail closed), not "not revoked". A's vault resync then sees the merged state. A revocation made at A while the publisher is unreachable reaches the host at the next publish, in the other direction: the publisher also ORs in A's list when it can read it.
- The host is a dumb file store (a static server in the demo, an object store later). It holds no key and cannot forge anything: an altered file fails verification.
- B's poller fetches `statusFetchUrl` with a conditional request (an unchanged list costs a "not modified" reply), verifies the list under the pinned `statusIssuerDid` key, and applies the ADR 0013 rules unchanged: OR the bits in, never clear; freshness from the signed `validFrom`; reject future-dated or too-old lists; malformed index refused.
- Past `maxStatusAgeSeconds` B **denies** every agent of that anchor (`FOREIGN_STATUS_STALE`). Recovery is automatic on the next fresh list.

### 4. B can distrust a whole domain

`enabled: false` on an anchor denies all of that domain's agents at once, with no network. It is B's own control, for a vanished or compromised A. It is a blunt tool, not a substitute for per-agent revocation.

### 5. Where it lives

- Pure verification (`verifyForeignAgent`, anchor and policy types, the status-view logic) with an injected clock **and an injected replay cache** (it holds state): in `packages/core`, no I/O (§3). Anchor/request/denial shapes: `packages/contracts`.
- The poller, cache and a verifier a B-side process can embed: a new `packages/federation` (justified: it needs I/O and caching, so it cannot be in core, and the SDK must stay free of `@custos/core`).
- The publisher: a command in `apps/admin` (`custos-admin publish-status`), because it needs direct DB and key access like `key create`.
- No new service, and no edge-verifier service (CLAUDE.md §2).

### 6. Out of scope (not built, interfaces left open)

A2A / MCP integration (the credential travels in a header so an A2A Agent Card can later advertise it); a push channel (websocket or webhook) for faster revocation, since the poll is needed for freshness anyway; cross-domain key rotation; multi-hop delegation; OpenID Federation; sidecars; the data proxy.

## Credential lifetime (direction, not part of this build)

The founder wants an agent's authority to end on a time limit, on its task being done, or when its credits run out. These differ in kind, and the difference decides where each is enforced:

| Condition             | Statically signed into the credential? | How a foreign verifier learns it                                                   |
| --------------------- | -------------------------------------- | ---------------------------------------------------------------------------------- |
| **Time limit**        | Yes: `validUntil`                      | Locally, offline, no freshness problem                                             |
| **Task done**         | No: it happens later                   | As a revocation (reason `completed`), through the same list and publisher          |
| **Credits exhausted** | No: it is a running count              | As a revocation (reason `budget-exhausted`), raised by whatever meters the credits |

So only the time limit is a credential field. The other two are _triggers for revocation_ and ride the machinery this ADR builds, with the same freshness guarantees. Credit metering is a new component (a counter on the hot path, a budget policy, who tops it up) and is **not** designed here: it needs its own ADR, is beyond Phase 6, and is to be logged on the Notion "13 — Additional features" page once the founder approves the scope. Phase 6 includes only: the verifier honours `validUntil` when present, and the revocation record carries a reason.

## Alternatives considered

- **A's revocation service signs on request, B calls it.** Simple, but B then depends on A's server; fails the DONE criterion.
- **B keeps trusting its cache forever while A is unreachable.** Offline works, but a revoked agent keeps working and revocation cannot be guaranteed. Rejected by the fail-closed rule.
- **Revocation only by B's `enabled: false`.** Works offline but cuts off every agent of A; no per-agent revocation. Kept as an addition, not the mechanism.
- **Push only (webhook or websocket).** Faster, but silence is ambiguous and gives no freshness proof; also needs B reachable inbound across organisations. Deferred as an accelerator.
- **Resolve A's `did:web` at verify time.** Needs A's server; rejected. A cached DID document is a weaker version of a pinned key and adds a TTL to reason about.

## Consequences

- A deliberate trade: if the publisher or the host is down for longer than `maxStatusAgeSeconds`, B stops accepting A's agents. That is the fail-closed choice, and the window is set by the operator per anchor.
- The publisher is a new long-running, key-holding process with its own operational surface: it must be monitored, and a stopped publisher looks like an outage to every foreign verifier.
- Revoking through the publisher bypasses the revocation service's control-plane audit path (service off). Revocations made this way must still be audited; how, with the audit service possibly off, is an open question below.
- **Credential lifetime (founder, 2026-10-17: expiry should exist, driven by a time limit, task completion, or credit exhaustion).** See the section below. This ADR requires only that the verifier honour `validUntil` when present.
- **Agent credentials do not expire today** (`services/identity/src/agents/register.ts` sets `validFrom` only, no `validUntil`). Across organisations that leaves revocation as the only control over a leaked credential. Whether to add an expiry (and renew) is a separate decision, flagged here and not made.
- **B audits its own decisions.** Every accept and deny of a foreign agent is recorded by B with the foreign DID, the anchor's domain, the decision and the reason (CLAUDE.md §10). A's audit service is not involved.
- The existing intra-org vault path is untouched; its pinned-issuer-by-DID approach (ADR 0013) stays. Federation adds a second, key-pinned verifier path and does not replace it.

## Implementation notes (step 1, 2026-10-17)

- **Namespace rule.** B refuses a credential whose subject DID does not start with `<issuer DID>:`. Without it, two trusted organisations could sign credentials naming each other's agents, and anything keyed on `agentDid` alone would be wrong. Custos agent DIDs are `<issuer DID>:agents:<id>` and the issuer DID is `did:web:<domain>` with no path, so every credential Custos issues satisfies it. **Anything B records or authorises on a foreign agent must still be keyed on the pair (issuer, agent DID).** The replay key is `<issuer>|<agent>|<jti>`.
- **A status view is bound to its anchor.** A `VerifiedForeignStatusList` carries the `statusListId` it was verified for; `verifyForeignAgent` refuses a view whose id is not the anchor's (`STATUS_VIEW_MISMATCH`) and `applyStatusList` throws when asked to merge two different lists.
- **Replay memory is one second longer than the first draft.** `verifyPossessionProof` floors `now` to whole seconds, so a proof is accepted until just before `(iat + skew + 1)` s. `proofReplayExpiresAtMs` in core is the one place that rule lives; the first draft (and the vault since Phase 5b) remembered a proof id only until `iat + skew`, leaving up to a second in which a captured proof could be replayed. Fixed in the vault in the same change, with a test that failed first.
- **Resolved by ADR 0015 (2026-10-24): the proof now binds tool and action.** Was: **Not covered by the proof (decide at step 4, when a call shape exists).** The foreign-call proof binds type, audience, time and id, not the request (no method, path or body hash, as DPoP's `htm`/`htu` would). A proof captured in flight could be spent once, on a different action, before the agent uses it. If the receiving side's actions differ in weight, add a request binding.
- **Denials stay inside core** as discriminated unions (`ForeignDenial`, `ForeignStatusListError`); mapping to `packages/contracts` codes and the anchor's Zod schema belong to step 4, which is where the config is read. Core does not depend on contracts.
- The signing library's JSON-LD context rejects some shapes (a status entry with another `type`) at issuance, so they cannot be signed; the verifier checks them anyway, and `verify-agent.defensive.test.ts` reaches those checks by stubbing the signature step.

- **A's own reads stop when it cannot confirm the published list (decided 2026-10-18 by the founder, "Option 1"; recorded at step 2).** The union merge also runs on a schedule, not only at start, because a publisher-only revocation made while A is running must reach A. When the merge feature is on (`REVOCATION_PUBLISHED_LIST_URL` set), A's revocation service answers `GET /status/revocation` and `GET /revocations` with 503 `PUBLISHED_STATE_UNKNOWN` until a published list has been verified, and again once the newest verified list is past its `notAfter` (its signed `validUntil`, bounded by `REVOCATION_PUBLISHED_MAX_AGE_SECONDS`). A's vault then fails closed through its existing staleness rule. `POST /revocations` and `POST /agents` keep working throughout: revoking is the emergency path and must not wait on the publisher. A dead publisher or host therefore stops A's own agents once the window passes, the same rule B applies; the window is per-deployment configuration (a longer window for A than for B is allowed). With the URL unset the feature is off and behaviour is unchanged, **once migration `0009` has been applied** (the served list always reads the new table, so a database without it makes `GET /status/revocation` fail and the vault deny everything: migrate before deploying this code). Rows merged while the feature was on are still served after it is switched off, so switching it off never quietly un-revokes an agent.
- **Stale lists still contribute their revocations.** A correctly signed list that is past its window is merged for its bits (a revocation is permanent, so they are still true) but does not reopen the gate. The merge uses the stale-tolerant mode of `verifyForeignStatusList` (`acceptStale`).
- **Merged revocations are audited** as a `service` principal acting on its own, with the fixed reason `published-list` (the bitstring carries no reason). An index with no row in A's database is stored in its own table so A's served list can never clear a bit the publisher set.
- **Step 3 must not depend on the gated endpoint.** `GET /status/revocation` on A is closed exactly when the publisher is recovering from its own outage. The publisher merges A's revocations into its own state; if it read them through that endpoint it would get 503 and could publish a list missing A's own revocations, so B would accept an agent A revoked until the next cycle. The publisher reads A's revocations from A's database, or accepts that window explicitly; decide at step 3.
- **Reason needs no work in step 2.** Revocations already carry a reason in the database and in the signed tombstone.

## Implementation notes (step 3, the publisher, 2026-10-21)

Decided by the founder: **(A)** the operator names the agent to revoke by its credential file; a raw status-list index is only a fallback and must be typed twice. **(B)** the publisher's own journal is the interim record of who revoked what and why; copying it into the audit service is a separate follow-up.

- **Where.** `custos-admin publish-status <init|revoke|once|run|show>` in `apps/admin/src/publisher/`. File sink only: the list is written to `--out`, a path a static server (or a bucket sync) serves. Object-store sinks, a push channel and the KMS move are not built. **The publisher is not production-ready until its key moves to KMS** (its signing key is a seed in `CUSTOS_PUBLISHER_SIGNING_SEED`, environment only: never a flag, never logged, never written to the state or journal).
- **The journal is the record of truth; the signed list is a cache.** One JSON line per revocation (`index`, `at`, `operator`, `reason`, optional `agentDid`), appended and fsynced _before_ any list is signed. A signed state file only proves it was not edited; it cannot prove it is not an older copy, so deleting or rolling back state would otherwise re-sign an old list with a fresh `validFrom`. Every cycle builds the list from the union of: the journal, the last signed state (if it verifies under this key), the copy at the sink or `--host-url` (if it verifies), and, optionally, A's database (`--use-database`, read with explicit connection and statement timeouts so a switched-off database host cannot stall a publish; if it cannot be read, stamping continues and the failure is reported). A source that fails verification is ignored with a warning, never merged. `init` is refused when a list signed by this key is already served, and also unless it was either given a host to ask (`--host-url`, where only a 404 means there is none) or told by the operator that nothing was ever published (`--confirm-nothing-is-published`); otherwise an empty list could replace a real one on a new machine. With no journal, no verified state, no verified host copy and no `init`, the publisher refuses to publish. **A list for this very identity that was not signed by the configured key (the wrong seed) is a hard `KEY_MISMATCH` refusal, not an ignored copy**, because replacing it would make A and every B reject the new list and fail closed with the good copy gone; a list for a different identity is ignored with a warning.
- **Appending is crash-safe.** Before each append the journal is cut back to its last newline, so a crash mid-append (which was never acknowledged or published) cannot be glued onto the next entry and make the journal unreadable, which would stop the publisher for good.
- **One writer.** `revoke` appends to the journal and then publishes under an exclusive lock file (stale-lock handling by age, bounded wait). The lock carries a token: a holder releases it only if it is still its own, and checks again just before writing the list, so a slow publish whose lock was taken over writes nothing (`LOCK_LOST`) instead of overwriting a newer revocation. The cycle reads the journal _inside_ the lock, so a revocation made during a cycle is in the next publish, never lost. `run` is a loop of locked publishes.
- **Naming the agent.** `revoke --credential agent.json` reads the agent's index from the credential and checks the credential's signature against A's pinned identity key (`--identity-public-key`), and that its `statusListCredential` is this publisher's list. `revoke --index N --confirm-index N` is the fallback. `--operator` and `--reason` are required (no defaults): they are what the journal records.
- **Writes.** The list is written to a temporary file in the same directory, fsynced, and renamed over the target, retrying a bounded number of times on `EPERM`/`EBUSY`/`EACCES` (Windows refuses a rename over a file another process holds open). A failed write is an error, never logged as published.
- **Configuration refuses to boot:** the validity period and the stamp interval are required with no defaults, and the stamp must be shorter than the validity period. An index must be a decimal safe integer below `MAXIMUM_STATUS_LIST_BYTES * 8`.
- **One identity derivation.** The revocation DID and list URL for a domain come from one core helper used by both the revocation service and the publisher, so they cannot drift; a list the publisher signs is tested against A's own reconciler and against `verifyForeignStatusList` built from A's published DID document.
- **The publisher reads A's revocations from A's database or not at all** (never through the gated `GET /status/revocation`).
- **The stamp interval must be shorter than every receiver's window, and nothing can enforce that.** The publisher checks only that `--stamp-seconds` is shorter than its own `--validity-seconds`. A's `REVOCATION_PUBLISHED_MAX_AGE_SECONDS` and each B's `maxStatusAgeSeconds` must also be longer than the stamp interval (with room for a missed stamp), or their gates close between stamps.
- **The operator machine's clock is now on the trust path:** it sets every list's `validFrom`, so it needs NTP.
- **The journal is interim evidence, not the audit trail.** Who revoked and why lives in a file on the operator's machine until a follow-up replays it into the audit service (which needs a service key with `audit:write`).
- No new external dependency: `apps/admin` gains `@custos/core` (a workspace package).

## Implementation notes (step 4, `packages/federation`, 2026-10-22)

- **Core change first: post-proof denials now say who.** `STATUS_ENTRY_INVALID`, `STATUS_UNAVAILABLE`, `STATUS_VIEW_MISMATCH`, `AGENT_REVOKED` and `STATUS_STALE` carry `{ agentDid, issuerDid, domain }`, attached only after the credential signature and the proof of possession verified. The gate audits on that and never re-reads the raw input, so a later reorder of core's checks cannot make it audit an attacker-chosen DID.
- **Public answers are coarse and exhaustive.** `toPublicDenial` is an exhaustive `switch` (a new core code fails typecheck): credential, proof, anchor, replay and unusable-status-entry failures all answer `401 UNAUTHORIZED`; `AGENT_REVOKED` is `403`; a missing, stale or mismatched list, or a full replay guard, is `503 UNAVAILABLE` (retryable, still refused). `@custos/contracts` gains `AGENT_REVOKED` (the string the vault and SDK already use) and `UNAVAILABLE`. An exception inside the decision (a shared replay store down) also answers 503 and is never let through.
- **Audit rule.** Allows and the five post-proof denials above are audited; everything earlier is passed to `onDenied` (for the embedder's log) and never audited, so an unauthenticated caller cannot fill the evidence log (ADR 0008). A revoked agent that keeps calling is audited each time, as the vault does. Record shape: `agentDid` = the foreign DID, `policy.rule` = `foreign:<domain>`, `reason` = `issuer=<DID> code=<CODE>`; `tool` and `action` are passed in by the embedder (default action `foreign.call`). `AuditRecord` is unchanged.
- **Status cache.** Fetches only the configured `statusFetchUrl`, `redirect: "error"`, a timeout that also covers reading the body, a byte cap counted as bytes arrive. Validators (`ETag`, `Last-Modified`) are stored only from a body that verified, are sent only while a verified view is held, and a 304 never moves freshness (only a newer signed `validFrom` does). One fetch in flight per anchor; a timeout chain, not an interval; `stop()` aborts the fetch and the wait. Failure keeps the last view without extending it, so it ages into `STATUS_STALE`. The view is memory only: after a restart B denies (`STATUS_UNAVAILABLE`) until the first poll succeeds.
- **Anchor config.** `parseTrustAnchors` refuses duplicate `credentialIssuerDid` or `statusListId` (the first match would otherwise win silently), requires https for the fetch URL except loopback hosts (checked on the parsed hostname, so `localhost.evil.com` fails), and requires `maxStatusAgeSeconds` and `enabled`.
- **Resolved by ADR 0015 (2026-10-24).** Was: **The proof still does not bind the request** (open item from step 1). The gate takes `tool` and `action` for the audit record, but the foreign-call proof does not cover them, so a proof captured in flight could be spent once on a different action within the skew window. No call shape exists yet to bind to (the gate has no HTTP surface in this step); decide when an embedder defines one.
- **One replay guard per verifier process.** The in-memory guard is correct for one process; several instances need a shared store behind `ForeignReplayGuard`.

## Implementation notes (step 5, the two-stack e2e, 2026-10-22)

- **Where.** `apps/admin/src/federation.e2e.test.ts` (`apps/admin` owns the publisher), run by `test:e2e` only.
- **"A is off" on one machine.** A's identity and revocation services are closed and A's database is set `ALLOW_CONNECTIONS false` with its sessions terminated; the test asserts the ports refuse and a fresh connection fails. Both organisations share one Postgres server, so this is not the build plan's "two machines".
- **Proved, not assumed:** every request B makes is recorded and is to the static host; B refuses the revoked agent within one poll interval (measured); the stale window and the recovery leg from the negative-test list (a stopped publisher fails closed after the window and recovers on the next list), with the revoked agent answered 403, never 503, throughout; B's audit records verify under B's audit key.
- **Time.** One clock (`Date.now()` plus an offset) for B, the publisher and the agents' proofs; the stale phase moves the offset past the window instead of waiting. Windows (30 s) and the poll interval (300 ms) are set through configuration only.

## Negative tests that must exist

A credential signed by an unknown key; by a different domain's key under the anchor's DID; a tampered credential; an expired credential; a copied credential without its private key; a replayed proof; a proof for the vault replayed at B and the reverse; a list signed by another key; a tampered list; a list older than `maxStatusAgeSeconds`; a future-dated list; a replayed old list (refreshes only its remaining window); a list that omits a known revocation cannot clear a bit; a status entry pointing at a foreign list URL; oversized or malformed input; a disabled anchor; no anchor configured for the issuer; a stopped publisher fails closed after the window and recovers on the next list; a list whose `validUntil` has passed; the publisher revokes with A's database stopped and the host's copy is lost (the publisher republishes from its own state); **A restarts after a publisher-only revocation and shows the agent revoked** in its own list and in its own vault, and answers "unknown" until the merge has succeeded (the union rule, section 3).

## DONE criterion, as an e2e

Two independent stacks (separate Postgres databases, seeds, DIDs, ports) plus a static host on a third port. A registers an agent; B verifies it. **All of A is stopped, its Postgres included.** B still verifies (inside the window). The operator publishes a revocation through the publisher. B rejects within one poll interval. Then the publisher and host are stopped and, after `maxStatusAgeSeconds`, B denies everything from A.

## Open questions

**Decided 2026-10-17 by the founder (kept for the record):**

1. **"Machine A is off" includes A's database. Chosen: (a).** The publisher in section 3 reads A's Postgres. If A's whole machine is off, so is its database, and that cannot work. Two ways out: (a) the _published list is the publisher's own state_: it fetches the current list from the host, verifies it, sets the bit at the agent's `credentialStatus` index, re-signs and publishes, needing no access to A's database; or (b) "machine A" means A's services, and its database lives elsewhere. (a) is the stronger demo; (b) is honest but weaker.
2. **One source of record for the list. Chosen: Fix 1, publisher state merged into A by union (section 3).** With (a), the publisher signs revocations that A's own database never saw. When A comes back, its revocation service would serve a list missing them, and a cold-restarted vault of A would let the agent work again inside org A. Either the publisher writes back to A's database once reachable, or the publisher becomes the only signer of the list. This must be chosen, with a negative test.

**Non-blocking:**

3. **Decided 2026-10-17 (founder): design for production, not for the demo.** The freshness window is required configuration on both sides, with no default in code: `validUntil - validFrom` on the publisher (A) and `maxStatusAgeSeconds` on each anchor (B). Documented recommendation: a window of 1 hour, a stamp (re-sign) every 20 minutes, and a **revocation published immediately** when it happens, not at the next stamp. Tests and the e2e run the same code with short values (seconds) through that configuration; nothing is special-cased for the demo. The stamp is accepted as necessary: silence cannot prove that nothing changed.
4. **Auditing a revocation made while the audit service is off. Decided 2026-10-21 (founder): the publisher's journal is the interim record** (who, when, which slot, why), kept on the operator's machine; replaying it into the audit service (a service key with `audit:write`) is a separate follow-up, not built. Until then it is not tamper-evident.
5. **Publisher signing key. Decided 2026-10-17 (founder): keep the revocation identity** (`REVOCATION_ISSUER_DID`), so A's own vault trusts published lists unchanged. The key must not be copied around as a seed: in production it is held in KMS behind `KeyProvider` (ADR 0012's consequence that revocation signing moves to KMS becomes a prerequisite for a production publisher). A local seed remains for development only.
6. Whether a stopped anchor should keep **revocations already seen** forever (yes by the never-clear rule) when `enabled` is toggled back on.

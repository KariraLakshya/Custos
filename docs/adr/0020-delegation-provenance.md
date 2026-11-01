# 0020: Delegation provenance — signed hand-offs that only narrow, checked locally by the vault

**Status:** Proposed 2026-11-02 (Phase 8, ADR 0018). The founder answered its four questions the same day, each as recommended (see "Founder decisions"). Accepted when the Phase 8 pull request merges.

## Context

Phase 8's DONE (`docs/build-plan.md`): an agent acting for a human through one sub-agent gets a token, and its audit record carries the full chain, verifiable by `custos audit-log`. A chain with a forged, unsigned or expired link is refused. A sub-agent asking for a tool or action its delegator was not granted is refused. Revoking any link refuses every agent below it within the revocation bound. The chain is checked without any network call.

What exists today:

- **Grants.** `agent_policies` (vault) is `(agent_did, tool)`: tool-level, no actions, and **no record of who granted it**. The grant's principal reaches the audit ledger (ADR 0008 §7) but not the vault's table, and the ledger cannot be read on the token path (CLAUDE.md §3).
- **Tokens.** `POST /tokens` verifies the agent's credential against the trusted identity issuer. The issuer's DID document is resolved once and cached for the process (`tokens/trusted-issuer.ts`). It then checks the ADR 0015 proof, bound to tool and action, checks the grant, and issues a 60 s token (ADR 0003) whose `sub` is the agent.
- **Revocation.** The vault's cache (ADR 0013) learns an agent's status-list index from that agent's signed credential when it asks for a token. `/call` asks `verdict(sub)`. An agent the cache has not seen is `unknown`, and `/call` refuses it as `REVOCATION_STATE_UNKNOWN_AGENT`.
- **Audit.** `AuditRecord.authorityChain` is `[agentDid]`, built flat so that a chain extends it without a shape change (Phase 4). Records carry `dataCategories` (static per connector) and `policy.rule`.

### Prior art read for this decision

- **Delegate SD-JWT.** Adopted by the IETF OAuth WG as `draft-ietf-oauth-delegate-sd-jwt-00` (26 Oct 2026, expires 29 Apr 2027), from the individual `draft-gco-oauth-delegate-sd-jwt-00` (Google). Each hop is a key-binding JWT that is itself an SD-JWT, signed with the key named by the previous hop's `cnf`, and linked by `sd_hash`.
  - Narrowing means only _withholding disclosures_.
  - It defines **no scope or constraint rule, no subset check, no depth limit, no per-hop expiry rule and no revocation** (§8.3: a holder "can not easily distribute revocation information").
  - Its main security warning (§8.1): verify the binding _in both directions_, or a delegate can splice chains when a `cnf` key is reused.
  - Algorithms are left to RFC 9901.
- **AIP** (arXiv 2603.24775, reference implementation `sunilp/aip`, Apache-2.0).
  - Ed25519, with Biscuit append-only blocks and Datalog checks.
  - The rule is "each delegation block MUST be a subset of its parent's capabilities", with a `max_depth` (default 3).
  - It has **no revocation** ("relies on short-lived tokens") and no binding of a token to a call (replay inside the TTL is left to transport).
  - Identities are its own `aip:web` / `aip:key`, not DIDs.
  - Its README warns that **"any prefix of a valid JWT chain also verifies and carries an earlier holder's wider authority"**.
- **Not read:** RFC 9901 itself, AIP's `SPEC.md`, and the full text of the WG `-00`; the individual `-00` and the datatracker pages were read. AP2's use of Delegate SD-JWT is known only from secondary sources (Notion page 09). **No interoperability is claimed by this ADR.**

What neither provides is what Custos already has: revocation of any participant that takes effect everywhere within a second, offline verification against a known issuer, and a sealed audit ledger.

## Decision

### 1. The root of every chain is a vault grant, and the grant names who made it

`agent_policies` gains `granted_by`: the principal from `principalOf(request)` on `POST /policies`. That is an operator key's name and ID, or an SSO operator's subject and email (ADR 0010). Re-granting an existing grant updates `granted_by`.

The migration is versioned and reversible. Existing rows get `NULL`. **A grant with no `granted_by` still works for the agent itself, but cannot be delegated** until an operator grants it again. That way no chain ever starts from an unknown authority.

"The human" in the DONE is this principal. The audit record states which kind it is (SSO person or named key) rather than calling a key a person.

A grant is tool-level. **The root holds every action of that tool; hand-offs narrow by action.** No change to grants is needed for action-level delegation.

### 2. A hand-off is a signed envelope from the delegating agent

A hand-off is a compact envelope, `base64url(JSON).base64url(signature)`, the same family as tokens, tombstones and seals (ADR 0003, 0005, 0017). It is signed by the **delegating agent's own key** (ADR 0007; the key never leaves the agent):

```
{ typ: "custos-delegation+v1",
  iss:  <delegator agent DID>,
  sub:  <delegate agent DID>,
  grants: [ { tool, actions: [ ... ] } ],   // non-empty, explicit actions
  depth: <further hand-offs allowed below this one, >= 0>,
  prev:  <base64url SHA-256 of the previous hand-off's compact form> | null,
  iat, exp, jti }
```

- A **chain** is the ordered list of hand-offs plus each delegator's agent credential. The credentials let the vault learn each delegator's public key and status-list index with no fetch.
- The delegate must itself be a registered Custos agent: it proves possession of its key on `/tokens` (ADR 0015).
- No new cryptography: Ed25519 via `@noble/ed25519` and SHA-256 via `@noble/hashes`. Only the existing primitives are used.

**Field mapping, for a later Delegate SD-JWT encoding:** `iss`/`sub` ≈ issuer and holder, the delegate key ≈ `cnf`, `prev` ≈ `sd_hash`. A later ADR can add that encoding behind the same verifier if the draft matures and interop is shown. Nothing here assumes it.

### 3. The verifier, pure, in `packages/core` (`delegation/chain.ts`)

`verifyDelegationChain({ chain, requesterDid, tool, action, rootGrants, trustedIssuer, now, limits })` returns a discriminated result (CLAUDE.md §7). It checks:

- **Size:** at most `limits.maxLinks` hand-offs and `limits.maxBytes` in total, checked before any parsing beyond length.
- **Each delegator credential:** it verifies against the trusted identity issuer (the existing verifier), is unexpired, and its subject equals that hand-off's `iss`. The hand-off's signature verifies under that credential's key.
- **Two-way binding**, the Delegate SD-JWT §8.1 lesson:
  - hand-off _i+1_'s `iss` equals hand-off _i_'s `sub`;
  - hand-off _i+1_'s `prev` equals the hash of hand-off _i_;
  - hand-off 1's `prev` is `null`.

  A hand-off spliced in from another chain fails one of these.

- **Never widens:**
  - every `{tool, actions}` in hand-off _i+1_ is within hand-off _i_;
  - hand-off 1's tools are within the root grants of its `iss`, with all actions;
  - `exp` ≤ the parent's `exp`, and ≤ `iat + limits.maxLifetime`;
  - `depth` < the parent's `depth`, and hand-off 1's `depth` ≤ `limits.maxDepth − 1`;
  - expired or not-yet-valid hand-offs are refused, with the existing clock-skew bound.
- **Ends at the requester:** the last hand-off's `sub` equals `requesterDid`, whose key the ADR 0015 proof has already proven. This closes AIP's prefix problem. A truncated chain names someone else as its last holder, so presenting it means being that agent.
- **Covers this request:** `{tool, action}` is within the last hand-off.

No network call is possible from it: the issuer's document is passed in.

### 4. Where it runs: `POST /tokens`, then every `/call`

When a token request carries a chain:

1. The vault runs the verifier.
2. It reads the **root grant** of hand-off 1's `iss` from its own database. This is the same indexed lookup as today's `isToolAllowed`, now also requiring `granted_by` non-null.
3. It **tracks every delegator** in the revocation cache from its credential, so a delegator that has not asked for a token itself is `ok` or `revoked`, never `unknown`.
4. Every chain DID must be `ok` and the cache not stale.

The requester needs no grant of its own.

The issued token gains a `chain` claim: the DIDs from the root delegator to the requester (ADR 0003 extension). `/call` checks `verdict` for **every** DID in it, so revoking any one of them refuses the call at the next request. The existing ~1 s push bound and fail-closed staleness apply unchanged.

### 5. What revoking a link means

- **Firing (revoking) an agent anywhere in a chain refuses every agent below it.** This needs nothing new beyond §4.
- **Cancelling one hand-off without firing anyone** is _not_ in this design. Hand-offs are short-lived instead: `maxLifetime` default 1 h, and never past the parent.
- **Taking a tool back from the root agent** needs an ungrant endpoint, which does not exist yet (the Risk page lists "no way to remove a single permission" as planned). With one, the root lookup in §4 refuses the chain at the next token request (≤ 60 s). Without one, firing the root agent is the way.

The founder decided (2026-11-02) that firing is enough for Phase 8: neither per-hand-off cancellation nor an ungrant endpoint is built in this phase.

### 6. The audit record carries the evidence, not just the names

For a delegated call the vault reports:

- `authorityChain: [rootDelegatorDid, …, requesterDid]`;
- `policy.rule: "delegation:<tool>"`, the same pattern as `foreign:` (ADR 0014);
- a new optional field `delegation: { root: { principal, tool }, handOffs: [compact…], credentials: [ … ] }`.

`custos audit-log` re-runs `verifyDelegationChain` on it offline against the identity issuer, so the chain is _checkable_ by an auditor, not the vault's word.

It also prints the chain as "<principal> → A → B". The root grant's own audit entry (`policies.grant`, with its principal) is in the same sealed ledger.

The cost is a larger entry (hand-offs plus up to `maxLinks` credentials) on the open `GET /records`. Credentials hold DIDs, public keys and status indexes, nothing personal. `dataCategories` stays the connector's declared list.

### 7. Developer surface

- SDK `delegate({ to, grants, ttl })`: the delegating agent signs locally and returns the hand-off. There is no control-plane call; Custos first sees the chain when it is used.
- SDK `connect(tool, { delegation })`.
- CLI `custos delegate --to <did> --tool <t> --action <a> [--ttl]` writes a hand-off file, and `custos use … --delegation <file>`.

### Limits (configuration, validated at boot)

`DELEGATION_MAX_LINKS` (default 3; the DONE needs 1), `DELEGATION_MAX_LIFETIME_SECONDS` (default 3600), `DELEGATION_MAX_BYTES` (default 16 KiB). Not bypassable: a chain over any limit is refused.

## Alternatives considered

- **Delegate SD-JWT now.** It is a standard carrier, but Custos would still write the scope rule, subset check, depth limit and revocation itself. It is a `-00` WG draft and will change. It also adds a JWT/SD-JWT stack beside the JSON-LD credentials and compact envelopes.
  - _Rejected for now._ The field mapping in §2 keeps the door open.
- **AIP / Biscuit.** It has real attenuation semantics, but:
  - Biscuit's JavaScript implementation is, as far as we know (to verify if reconsidered), a WASM build of the Rust library that carries its own cryptography, against CLAUDE.md §4's `@noble/*` rule;
  - Datalog is a policy-language attack surface (AIP itself recommends its simplest profile);
  - it has no revocation and uses non-DID identities.
  - _Rejected._
- **Delegation recorded by the control plane** (agent A asks Custos to register the hand-off). It gives central visibility, but adds a network call to delegate and a new write path, and gains nothing a signed hand-off does not give.
  - _Rejected:_ the offline property is the point (CLAUDE.md §3).

## Required tests (the DONE, plus what the prior art warns about)

Each must be proven in CI:

- **Positive:** an operator grants A `mock-database`; A hands B `{mock-database: [query]}`; B gets a token and calls it. The audit entry's chain verifies in `custos audit-log` and prints the principal → A → B.
- **Forged links:** a forged signature, an unsigned link, an expired link, a not-yet-valid link, and a delegator credential from another issuer or expired are each refused.
- **Widening:** another tool, another action, a later `exp` than the parent, a higher `depth`, too many links, and over-size input are each refused, and none consumes the proof's replay entry (ADR 0015 order).
- **Binding:** a link spliced from another chain (wrong `prev`), `iss` not equal to the previous `sub`, and a prefix presented by someone other than its last `sub` are each refused.
- **Root:** a grant with no `granted_by` cannot be delegated.
- **Revocation:**
  - revoking A refuses B's next `/call` within the bound;
  - B is refused even though A never requested a token itself (the `unknown` case);
  - revoking B leaves A working.
- **Offline:** the chain check makes no network call, with a fetch spy failing on any call.

## Not in this phase

Cross-company chains (federation), with `iss` resolution kept general so they fit later. Also not in this phase: inspecting data (categories stay declared), a DPDP export format, the sidecar, an SD-JWT encoding, per-hand-off cancellation, and an ungrant endpoint (founder, 2026-11-02).

## Consequences

- New: one migration (`granted_by`), the `chain` token claim, the optional audit `delegation` field, and the `delegation:` policy rule. All are additive; old tokens and records still verify.
- `custos audit-log` gains a chain check, so a ledger entry with a forged chain fails verification like an edited payload.
- Grants made before this change must be re-granted before they can be delegated. That is one command per grant.

## Founder decisions (2026-11-02)

1. **Format:** Custos's own signed hand-off (§2), mappable to Delegate SD-JWT later. Not the draft now, not AIP/Biscuit.
2. **Revoking a link:** firing an agent, which cuts every agent below it (§4), is enough for Phase 8, with hand-offs kept short. No per-hand-off cancellation and no ungrant endpoint in this phase.
3. **Limits:** `DELEGATION_MAX_LINKS` 3 and `DELEGATION_MAX_LIFETIME_SECONDS` 3600, as in §"Limits".
4. **The human at the root:** the operator who granted the tool, recorded as an SSO person or a named operator key, with the record saying which (§1). Grants made with an operator key may be delegated.

## Sources

- Delegate SD-JWT: https://datatracker.ietf.org/doc/draft-ietf-oauth-delegate-sd-jwt/ (WG `-00`), https://www.ietf.org/archive/id/draft-gco-oauth-delegate-sd-jwt-00.txt (individual `-00`).
- AIP: https://arxiv.org/abs/2603.24775, https://github.com/sunilp/aip.
- RFC 9901 (SD-JWT): https://datatracker.ietf.org/doc/rfc9901/ (not read for this ADR).

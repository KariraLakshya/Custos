# 0020: Delegation provenance — signed hand-offs that only narrow, checked locally by the vault

**Status:** Proposed 2026-11-02 (Phase 8, ADR 0018). The founder answered its four questions the same day, each as recommended (see "Founder decisions"). All six steps built 2026-11-09 on `feat/delegation-provenance`; Accepted when the Phase 8 pull request merges.

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

## Implementation notes

Recorded as the phase is built (branch `feat/delegation-provenance`). Advisor review of the build plan, 2026-11-02: the chain check runs between the proof's signature check and its replay record, so a refused chain does not use up the proof; `custos audit-log` re-verifies a chain at the entry's recorded time against a pinned identity issuer; the no-network property is proven in core; the audit contract's size bounds must admit a full chain; a refused chain audits only the verified requester.

- **§1, `granted_by` is four columns** (`granted_by_kind`, `_id`, `_name`, `_via`; migration `0013`, additive; to reverse it, drop the four columns), not one, so "SSO person or named key" is its own field. `Principal` (`@custos/control-plane-auth`) gains an optional `via` (`custos-admin` | `sso`) from the key row's `created_via`; mTLS principals have none. Audit events still copy only kind, id and name.
- **§1, only an operator's grant is a root.** A service principal can in principle hold `policies:write`; decision 4 names an operator, so `rootGrantOf` returns null for a service-made grant as for a pre-`0013` one. `isToolAllowed` is unchanged: such grants still work for the agent itself.
- **§2, the builder is in the light entry.** `delegation/hand-off.ts` (`buildHandOff`, `handOffHash`, `HAND_OFF_TYPE`) is exported from `@custos/core/possession` so the SDK can sign hand-offs without the JSON-LD stack; `delegation/chain.ts` (the verifier) is in the main entry. A hand-off names at most 16 tools of at most 32 actions each.
- **§3, the verifier does not check the root grant.** It returns `rootDid`; the vault then checks `rootGrantOf(rootDid, tool)` in its own table. Only the requested tool has to be granted to the root: every tool a chain names is within the first hand-off, and each request checks that the root holds its own tool, so a tool the root lacks can never be used. Same effect as §3's "hand-off 1's tools are within the root grants", one lookup instead of all of them.
- **§3, `maxDepth` is `maxLinks`.** One limit, not two: the first hand-off's `depth` is at most `maxLinks − 1`, so a chain can never be longer than `maxLinks`.
- **§3, error codes:** `INVALID_LIMITS`, `MALFORMED_CHAIN`, `TOO_LARGE`, `TOO_MANY_LINKS`, `CREDENTIAL_INVALID`, `SIGNATURE_INVALID`, `WRONG_TYPE`, `BROKEN_LINK`, `NOT_YET_VALID`, `EXPIRED`, `WIDENED`, `WRONG_HOLDER`, `NOT_COVERED`, each with the 0-based `link` where it applies. The result's `expiresAt` is the earliest hand-off `exp` and delegator `validUntil`, for capping the token.
- **§4, the token's `chain` claim** (`ScopedTokenClaims.chain`, optional): 2 to 16 DIDs, non-empty strings, the last equal to `sub`, else the token is `MALFORMED_TOKEN`. Tokens without it verify as before.
- **§4, `POST /tokens` order:** issuer, tool, credential, proof signature, **chain** (`verifyDelegationChain`), replay record, the requester's revocation, then for a chain: track every delegator from its credential, every DID must be `ok`, `rootGrantOf(rootDid, tool)`; without a chain, `isToolAllowed` as before. The token's `exp` is the earliest of `iat + ttl` and the chain's `expiresAt`. New error `DELEGATION_DENIED { agentId, reason }` (403), `reason` is the verifier's code or `DELEGATOR_STATUS_INVALID`, `NO_ROOT_GRANT`, `CHAIN_ENDS_NOW`; `AGENT_REVOKED` gains `revokedDid` when the revoked agent is a delegator. Body field `delegation: { handOffs, credentials }`, at most 16 of each; the verifier's limits do the rest. Clock skew for hand-offs is `VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS` (both are agent-signed times). Env: `DELEGATION_MAX_LINKS` (default 3, max 15), `DELEGATION_MAX_LIFETIME_SECONDS` (3600), `DELEGATION_MAX_BYTES` (16 KiB, max 256 KiB).
- **§4, `/call`** checks `verdict` for every DID in `chain` (or `sub` alone); a revoked delegator gives `AGENT_REVOKED` for the caller with the delegator named in the audit reason; an unplaceable one gives `REVOCATION_STATE_UNKNOWN_AGENT`. An allowed delegated call is recorded under `delegation:<tool>`.
- **§6, evidence once, at issuance (founder's decision, 2026-11-09).** The full evidence is recorded on one entry, the token's issuance; each call entry carries the chain and a reference to it, not the evidence again. Reason: calls stay small and the hot path unchanged, and an auditor checks the chain in one place. Concretely:
  - **Token claim `dref`** (`ScopedTokenClaims`, ≤ 64 chars): `handOffHash` of the hand-off naming `sub`. Required with `chain` and forbidden without it, else `MALFORMED_TOKEN`. Each hand-off's `prev` commits to the one before, so this one hash fixes the whole chain.
  - **Audit contract** (`auditEventSchema`, all optional, additive): `authorityChain` (2–16 DIDs, ends at `agentDid`, never with a `principal`), `delegationRef` (with `authorityChain` only), `delegation: { root: { kind, id, name, via? }, handOffs, credentials, checkedAt }` (needs `delegationRef`; ≤ 16 of each; ≤ 256 KiB + 4 KiB in all, so the largest configurable chain fits and the event stays under the 1 MiB body limit). `AuditRecord` gains `delegationRef` and `delegation`; the audit service stores the reported chain in place of `[agentDid]` and puts the two new keys last, so a record without them serialises byte for byte as before (golden-payload test).
  - **Vault:** a delegated `/tokens` success reports one `allow` entry (`delegation:<tool>`, `reason: "token issued under delegation"`, the requested action) with the evidence. `checkedAt` is the vault's time of the check. The response is `{ token, expiresAt }` only: the evidence about other agents is not returned to the agent. Every `/call` with a delegated token, allow or deny, reports `authorityChain` and `delegationRef`.
  - **`custos audit-log`** re-verifies every delegated entry after the ledger verifies and before the seal is remembered. An issuance entry runs `verifyDelegationChain` at `checkedAt` against `--identity-issuer` (default `did:web:localhost%3A4001`; pinned by the auditor, never read from an entry; only its DID document is fetched). The proven DIDs must equal `authorityChain`, `handOffHash` of the last hand-off must equal `delegationRef`, and `checkedAt` must be no later than `recordedAt` + 300 s. A call entry, or any entry whose chain is longer than one, must match a verified issuance entry by reference, agent, tool, action and chain. Failures are `DELEGATION_INVALID { seq, reason }`, `DELEGATION_UNLINKED { seq }` and `DELEGATION_UNCHECKABLE { reason }` (issuer unresolvable or not pinned). Each one fails the log. Output gains `delegations: [{ seq, kind, chain: "<name> (operator, sso) → A → B" }]`, also printed on stderr.
  - **Limits:** the re-check uses the widest a vault can be configured to: 15 links, 1 day, 256 KiB, 300 s skew. So `DELEGATION_MAX_LIFETIME_SECONDS` gains a max of 86 400 and `VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS` a max of 300 (both were unbounded).
  - **Known limitation of evidence-once.** If the issuance report is lost, every call under that token fails as `DELEGATION_UNLINKED` and `audit-log` fails the whole log, with no recovery. The report is fire-and-forget with a 2 s timeout, so this can happen. Audit loss is already a bug (CLAUDE.md §3); this makes it a visible one. Every event the vault produces is tested against the audit contract, so a 400 does not cause it.
  - **Issuance entry details:** `dataCategories` is `[]`, because issuing a token touches no data. Issuance entries are matched to calls by reference, agent, tool and action together, because one hand-off can cover several tools and actions, each with its own token. `checkedAt` must also be no earlier than `recordedAt` − 300 s: a backdated time would revive an expired chain.
  - **Not checked by `audit-log`:**
    - Whether a `policies.grant` entry for the root agent and tool exists. That entry carries the root agent's DID, so an agent-filtered pull drops it.
    - Delegators' revocation status at the time.
    - Credentials issued under an identity key that has since been rotated out: they fail against today's DID document.
- **§7, step 6 (developer surface):**
  - **SDK.** `delegate(agent, { to, grants, ttlSeconds?, depth?, extending? })` returns a `Delegation { handOffs, credentials }`, signed locally from `@custos/core/possession` with no network call. `connect(agent, tool, { delegation })` sends it with every token request.
    - The default lifetime is 600 s (`DEFAULT_DELEGATION_TTL_SECONDS`), within a default vault's 1 h. The default depth is 0.
    - Extending a received delegation links to its last hand-off, appends the extender's credential, takes one less depth by default, and is capped at the parent's expiry.
    - It throws, rather than sending what the vault would refuse, when the extender is not the last holder, when the depth is 0 or does not shrink, on a tool or action it was not given, on an expired parent, and on an unreadable chain.
  - **CLI.** `custos delegate <tool> <actions...> --to <did> --credential <file> [--key] [--ttl] [--depth] [--extending <file>] [--out delegation.json]` writes the delegation file and never overwrites one. `custos use … --delegation <file>` sends it.
    - **Deviation from §7:** the tool and actions are positional, matching `use <tool> <action>`, rather than `--tool`/`--action`. This follows the founder's usability concern (Phase 8b): fewer flags to remember.
    - **Untrusted input:** a delegation file is checked before anything is sent: 1–16 non-empty hand-off strings and 1–16 credential objects with an `issuer`. Otherwise it fails as one line.
    - **Refusals give the reason:** a refusal now prints `denied: <code> (<reason>)`, e.g. `DELEGATION_DENIED (NOT_COVERED)`, `INVALID_TOKEN (EXPIRED)`.
  - **README:** a delegation walkthrough is added to the demo.
- **Required tests, where each is proven:**
  - **Positive:** `apps/cli/src/cli.e2e.test.ts` "delegation provenance (Phase 8 DONE)", on the real identity, revocation, vault and audit services:
    - an operator grants A; A delegates `{mock-database: [query]}` to B; B queries;
    - `pullAuditLog` re-verifies the chain against the pinned identity issuer and prints `<operator> (operator…) → A → B`, the issuance entry's root naming the operator's key.
  - **Forged links:** `packages/core/src/delegation/chain.test.ts` covers a forged signature, an unsigned or edited hand-off, an expired or not-yet-valid one, and a delegator credential from another issuer, failing verification, or outside its validity. In the vault, `issue.delegation.test.ts` covers a forged hand-off.
  - **Widening:** `chain.test.ts` covers another tool or action, a later `exp`, a depth that does not shrink, too many links, and over-size input. `issue.delegation.test.ts` proves a widened chain does not use up the proof. The e2e test covers B asking for another action (`DELEGATION_DENIED`, `NOT_COVERED`).
  - **Binding:** `chain.test.ts` covers a spliced link, an `iss` that is not the previous `sub`, and a prefix presented by someone other than its last holder. `issue.delegation.test.ts` covers `WRONG_HOLDER`.
  - **Root:** `issue.delegation.test.ts` covers no grant, and a pre-`0013` grant with no `granted_by`. `policy.test.ts` covers a service-made grant.
  - **Revocation:**
    - Revoking A refuses B: a token B already holds is refused at `/call` (the hot path) within 1 s of `deprovision` in the e2e test, and so is B's next token request. Mutation caught: the vault checking `sub` only fails the e2e test.
    - B is refused even though A never requested a token itself: in the e2e test, A makes no vault request at all before B; `issue.delegation.test.ts` covers it as well.
    - Revoking B leaves A working: the second e2e test.
  - **Offline:** `chain.test.ts`, "makes no network call", with a `fetch` spy.
  - **Not separately proven:** that each widening case leaves the proof unspent. One case is tested; all cases share the same code path (the chain is checked before the replay record).
- **Proof, step 6:**
  - **Tests:**
    - SDK `client.test.ts` +11: first link; extension; each refusal; a malformed key or grants; the delegation sent on every token request.
    - CLI `cli.test.ts` +17: the delegate command, including `--extending`, overwrite refusal, and bad `--ttl`/`--depth`; `use --delegation` sending and printing the reason; ten bad delegation files each refused with nothing sent; `--identity-issuer` reaching the chain check.
    - e2e +2.
  - **The e2e race:** the e2e test waits until the final audit entries have landed before the services shut down. Otherwise a report still arriving holds a keep-alive connection open, and Fastify's close waits for its 72 s keep-alive timeout.
- **Proof, step 5:**
  - **Tests:** core token +5 (`dref` rules) and record +10; contracts +15; audit +4 (the golden payload of a plain record and its hash, a delegated issuance and call stored and verifying, two 400s for a chain the reporter cannot attach); vault: issuance asserts `dref` and the evidence, `/call` asserts the chain and reference, the route asserts the issuance entry, the call entry and the `{ token, expiresAt }` response, and env bounds +5; CLI `delegation-audit.test.ts` 30 (including two actions under one hand-off, and a backdated check), the vault route test also parsing every produced event with `auditEventSchema` (a root with no `via` included) and `audit-log.test.ts` +3 (no issuer pinned fails and remembers nothing; an unlinked call fails).
  - **Mutations caught:** no chain-equals-evidence check, re-checking at today's time, no reference check, no chain match on a call, the log passing despite a failed chain check, the audit service ignoring the reported chain, `/call` not reporting the chain, a token without `dref`, issuance matched by reference only, no lower bound on `checkedAt`, data categories on the issuance entry, a null `via` sent.
  - **Full runs:** `turbo run lint typecheck test` (78 tasks) and `pnpm test:e2e` (21 tasks) pass.
- **Proof so far (steps 3–4):** core +7 token tests; vault `issue.delegation.test.ts` 11 (one link, two links, delegators tracked so never `unknown`, token capped by the hand-off, revoked delegator, revoked requester, untrackable delegator, no root and pre-`0013` root, widened chain does not use up the proof which then succeeds, forged hand-off, prefix by a non-holder, uncovered action), `invoke.test.ts` +4, `server.test.ts` +2 (route, 403, audit of the requester only, 400 on a bad body). Mutations caught: chain checked after the replay record, no delegator tracking, no chain revocation check, no root check, no `exp` cap, `/call` checking `sub` only. Full `turbo run lint typecheck test` (78 tasks) and `pnpm test:e2e` (21 tasks) pass.
- **Proof so far:** core 406 tests (`delegation/hand-off.test.ts` 6, `delegation/chain.test.ts` 26, including a `fetch` spy that fails on any call), 100% lines and branches on both files. Mutations caught: no `prev` check, no last-holder check, no narrowing, no depth shrink, no issuer-to-credential binding. Vault `policy.test.ts` 6; mutation caught: any granter kind as a root.

## Sources

- Delegate SD-JWT: https://datatracker.ietf.org/doc/draft-ietf-oauth-delegate-sd-jwt/ (WG `-00`), https://www.ietf.org/archive/id/draft-gco-oauth-delegate-sd-jwt-00.txt (individual `-00`).
- AIP: https://arxiv.org/abs/2603.24775, https://github.com/sunilp/aip.
- RFC 9901 (SD-JWT): https://datatracker.ietf.org/doc/rfc9901/ (not read for this ADR).

# 0013: The vault resyncs revocation from the signed status list

**Status:** Proposed 2026-10-13. Not accepted: no code is written until the user decides. Open questions are at the end.

## Context

ADR 0005 chose two mechanisms: a signed tombstone **push** (fast) and a Bitstring Status List (durable and publicly verifiable). The vault's periodic resync, its safety net for a missed push, uses neither of the cheap ones. It downloads `GET /revocations`, which is the list of every tombstone ever issued, and verifies each one's signature. The list is never pruned, so that cost grows with every revocation ever made.

Measured on 2026-10-13 against the real services and the dev database (1,064 revocations):

|                                                                              | Today (tombstone list)                 | Status list (`GET /status/revocation`) |
| ---------------------------------------------------------------------------- | -------------------------------------- | -------------------------------------- |
| Work the revocation service does per fetch                                   | 1,276 ms (it re-signs every tombstone) | 28 ms (one signature)                  |
| Payload                                                                      | 315 KiB                                | 1.0 KiB                                |
| Vault verification from cold (vault restart, or the revocation seed changes) | 3,507 ms (about 3.3 ms each)           | 2 ms                                   |

All three grow linearly with revocations on the left and stay near flat on the right (the list is a fixed-size gzipped bitstring, 131,072 entries minimum). PR #65 (remember what was verified) and PR #67 (stable revocation key) removed the routine cost. What remains is the **cold** path: a vault restart or a seed change re-verifies everything, about 3.5 s now and minutes at tens of thousands of revocations.

A second finding, not specific to the vault: the dashboard polls `GET /revocations` every 1.5 s (`apps/dashboard/src/index.html`), and the `pnpm demo` banner tells people to keep the dashboard open. With one open, the revocation service spends about 1.3 s of CPU per poll re-signing 1,064 tombstones, which is longer than the poll interval, in the same service that must deliver a push inside 2 s. That may have contributed to the `delivered: 0` seen on 2026-10-11; this was not measured. See "Separate fix" below.

## Decision

**The vault resyncs from the signed status list, and keeps the tombstone push as the fast path.** The push is unchanged.

1. **Resync.** Fetch `GET /status/revocation`, verify the credential against the revocation service's did:web key (one signature), decode the bitstring, and OR it into the vault's local view. The vault never clears a bit: revocation is permanent, so applying a stale or replayed list can only fail to add, never remove.
2. **Freshness comes from the signed `validFrom`, not from the vault's clock.** The cache's `freshAsOf` is set to the list's `validFrom` (never moved backwards), not to the time of receipt. Replaying a list that is 29 s old therefore does not buy a fresh 30 s; it buys the 1 s that is left. A `validFrom` in the future beyond an allowed skew is rejected, and so is one older than `REVOCATION_MAX_STALENESS_MS`. The skew is explicit config (`REVOCATION_LIST_MAX_CLOCK_SKEW_SECONDS`), as `VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS` already is, because the rule now depends on the revocation service's and the vault's clocks agreeing. Today a replayed old tombstone list looks fresh because its `asOf` is unsigned; this closes that.
3. **Index from the verified credential, for the list the vault trusts.** The vault already verifies the agent credential at `POST /tokens`. It now also reads `credentialStatus` from it and remembers `agent DID → index`. The list it trusts is identified by `REVOCATION_ISSUER_DID` (the list's URL is derived from that DID's domain, not from `REVOCATION_URL`, which is only where the vault fetches from). The vault requires: `statusListCredential` equals that URL, `statusPurpose` is `revocation`, and the index is an integer inside the list. On the fetched list it also requires `issuer` equal to `REVOCATION_ISSUER_DID`. Anything else is refused at `/tokens` (fail closed), and an out-of-range index is treated as denied, never as "not revoked". Verification uses `verifyCredential` with `staticDocumentLoader`, which resolves only bundled contexts and never touches the network, so no outside call joins the resync path.
4. **Hot path.** `isRevoked(did)` is true if the DID arrived by push, or its remembered index has its bit set. An agent whose DID has no remembered index and no push is **denied**, not allowed (fail closed).
5. **Bounded index map.** An index is kept only while a token for it could be alive (token TTL plus a margin), then dropped. An agent that returns re-enters at `/tokens`, where its bit is checked from its index. The set of DIDs that arrived by push still grows by one per revocation, as it does today; it could be dropped once the bit covers it, which this ADR leaves alone.
6. **Fan-out.** The connector `revoke()` call still needs a DID. A bit newly set by a resync is mapped back through the remembered `DID → index`, which covers exactly the agents with live tokens. An agent with no live token has nothing in a connector to cut off.

7. **Code this makes dead is removed in the same change.** Once the resync no longer reads tombstones, the verified-tombstone memory and the yielding loop from PR #65 protect nothing (every push is a new string, verified once), so they are deleted rather than left behind. The push path keeps its per-tombstone verification and its issuer-key re-resolution on rotation.

### Alternatives considered

- **Put the index in the scoped token** (a new claim). No fail-closed window and no map for the check, but it changes ADR 0003's format, and fan-out would still need an index-to-DID map. Rejected for now: the window below is at most 60 s and the SDK never hits it.
- **Incremental resync, "tombstones since X" (earlier "Fix 3a").** Cheap to build, but a cold start is still linear: a restarted vault has no X. Rejected.
- **Only memoize signed tombstones on the revocation side** (see below). Fixes the service's CPU and the dashboard, not the payload or the vault's cold start. Complementary, not a substitute.

## Consequences

- **No new cost today from the missing index after a restart.** The vault creates its token-signing key with `createKeyPair()` at every boot (`services/vault/src/server.ts`), so a token issued before a restart already fails its signature check. The "unknown index means denied" rule only becomes a visible cost if the token key is ever made persistent (KMS) or more than one vault runs. At that point the choices are to put the index in the token (changing ADR 0003) or to share the `DID → index` map (Redis). Neither is needed now.
- **`GET /revocations` stays.** The dashboard needs agent DIDs, which the bitstring does not carry. Nothing else reads it after this change.
- **Negative tests that must exist:** a list signed by another key is refused; a tampered list is refused; a list older than the staleness bound is refused and does not refresh; a list missing a known revocation cannot clear a bit already set; an agent with no remembered index is denied; a credential with a missing or foreign `statusListCredential` is refused at `/tokens`; a resync after a long outage still fails closed past the staleness bound; a list replayed at 29 s old refreshes only the remaining 1 s; a future-dated `validFrom` is refused; an out-of-range index is denied; a list signed by a new key after a seed change re-resolves the key once and applies.
- **Scope.** Vault resync, `/tokens` index handling, and tests. No token-format change, no new dependency, no change to the push.

## Separate fix (not part of this decision)

Memoize signed tombstones in the revocation service, keyed on the exact row contents. Ed25519 is deterministic and a revoked row never changes, so a cached string is identical to a fresh one. That takes `GET /revocations` from about 1.3 s to milliseconds for the dashboard and any other reader. It is small and independent, and should land before the demo is shown to anyone, since the demo keeps the dashboard open.

## Questions for the user

1. Accept the design as written, which keeps the token format and defers the index-in-token question until the token key becomes persistent or a second vault appears (recommended)?
2. Do the tombstone memoization first as its own small PR (recommended; it also stops the dashboard loading the service)?

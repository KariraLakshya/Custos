# Revocation

Revoking an agent cuts it off from every tool it can reach, in well under a second, and permanently. It is the reason Custos exists: one command instead of rotating keys at every tool by hand.

```bash
custos revoke <agent id> --reason "compromised"
```

## Two mechanisms, two jobs

Custos uses a **push** to make revocation fast and a **signed list** to make it durable and checkable by anyone.

**The push (fast).** The revocation service records the revocation, signs a **tombstone** ("agent X is revoked"), and pushes it at once to every subscriber in `REVOCATION_SUBSCRIBER_URLS` (by default the vault). The vault verifies the tombstone's signature against the revocation service's published key and adds the agent to its in-memory revocation view. The hot path reads that view, so the next call is refused without any network call. An end-to-end test proves an agent calling three tools is cut off from all three in under a second.

The vault's push endpoint needs no API key: what it trusts is the tombstone's signature. An unsigned or forged notice is refused (`401 INVALID_TOMBSTONE`).

**The status list (durable).** The revocation service also publishes a signed W3C **Bitstring Status List** at `GET /status/revocation`: one bit per agent, set when the agent is revoked, at least 131,072 bits long so its size doesn't reveal how many agents exist. Each agent's credential says which bit is its own. Anyone can fetch the list and the revocation service's DID document and check a revocation without trusting Custos's database.

## Push, don't pull; and catching up

Pushes can be missed (a vault restarting, a network blip). So every `REVOCATION_RESYNC_INTERVAL_MS` (10 seconds by default) the vault also fetches the signed status list and checks it:

- it must be signed by the revocation service's key and name its DID (`REVOCATION_ISSUER_DID` on the vault) and the expected list address;
- freshness comes from the list's **signed** `validFrom`, not from when it arrived, so replaying an old list buys nothing;
- bits are only ever **added** (OR), never cleared, so an older or shorter list can never un-revoke an agent.

## Fail closed, with bounded staleness

If the vault's view has not been refreshed within `REVOCATION_MAX_STALENESS_MS` (30 seconds by default), the vault **refuses every call** with `503 REVOCATION_STATE_STALE`, rather than risk letting a revoked agent through. A vault that has never synced starts in that state. It recovers by itself once the revocation service is reachable again.

The two services' clocks must agree to within `REVOCATION_LIST_MAX_CLOCK_SKEW_SECONDS` (5 by default), because the list's freshness is the revocation service's time.

An agent whose status bit the vault has not recorded yet is refused for that one call with `REVOCATION_STATE_UNKNOWN_AGENT`, never treated as "not revoked". Asking for a new token records it.

## What revoking means

- **Permanent.** A revoked agent cannot be restored. Register a new one.
- **Everything below it too.** An agent acting under a [delegation](/concepts/delegation) from a revoked agent is refused as well.
- **Registration depends on it.** The identity service reserves each agent's bit before issuing its credential, and refuses to register an agent it could not later revoke.

The output says how many vaults were told straight away (`Vaults told now: 1`). A vault that could not be reached refuses the agent after its next successful resync.

## Limits

- If pushes stop arriving, revocation can lag by up to the staleness bound (30 seconds), after which the vault refuses everything.
- The vault's revocation view and the replay cache are in memory: correct for one vault instance.
- The revocation signing key comes from `REVOCATION_SIGNING_SEED` in development, or AWS KMS ([Keep keys in AWS KMS](/how-to/kms-keys)). Keep the seed across restarts.

Sources: ADR 0005, ADR 0012, ADR 0013, ADR 0016.

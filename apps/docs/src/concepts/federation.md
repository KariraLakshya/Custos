# Federation

Federation lets **organisation B accept agents that organisation A issued**, without ever calling A, and keep refusing A's revoked agents even while A's services are switched off.

## The problem

B wants to let A's agents call one of its services. Asking A's identity service "is this agent real?" on every call would make B depend on A being up, and would put a network call on B's hot path. So B checks everything locally, from things it was told once.

## Three pieces

**B's trust anchor.** Once, out of band, B writes down for A:

- A's identity service DID and its public key, which signs A's agent credentials;
- A's revocation DID and its public key, which signs A's status list;
- the status list's identity (`statusListId`) and the address B fetches it from (`statusFetchUrl`, https only except for localhost);
- `maxStatusAgeSeconds`: how old a list B will accept. Required, with no default;
- `enabled`: switch it off to refuse every A agent at once.

Keys are **pinned**: B never resolves A's `did:web` at check time, and only ever fetches the configured address, never one read from a credential.

**A's publisher.** `custos-admin publish-status` runs on A's security operator's machine. It signs A's status list and writes it to a file that any static host serves (a bucket, a CDN). It needs nothing from A's services or database: it keeps its own journal of revocations, so A can revoke an agent with everything else switched off. It re-signs on every revocation and on a regular **stamp**, because the list's signed time is B's only proof that it is fresh. See [Trust another organisation](/how-to/federation).

**B's gate.** `@custos/federation` gives B two parts to embed in its own service:

- `createStatusCache` keeps a verified copy of A's list, polled from the configured address only, with a timeout and a size limit;
- `createForeignAgentGate` checks each call: A's signature on the credential, the caller's proof that it holds the agent's key and that the proof was made for exactly this tool and action, and A's list.

## What B answers

| Outcome                     | Answer                                                                                              |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| Allowed                     | The verified agent                                                                                  |
| Any bad credential or proof | `401 UNAUTHORIZED`: the same for every reason, so a caller can't probe which organisations B trusts |
| A revoked the agent         | `403 AGENT_REVOKED`                                                                                 |
| B has no fresh list for A   | `503 UNAVAILABLE`. It still refuses: fail closed                                                    |

The tool and action passed to the gate must come from B's own routing (the endpoint being served), never from a field the caller sets. B audits its own allows, and its refusals of genuine agents, in its own audit log.

## A's own services

A's revocation service can also merge the published list into its own state (`REVOCATION_PUBLISHED_LIST_URL`), so a revocation made through the publisher while A was off is not lost. While that is on and the newest list is too old, A's revocation service answers `503 PUBLISHED_STATE_UNKNOWN` and A's vault refuses calls: A's own agents stop if the publisher stops. It is off by default.

## Limits

- Proven by an end-to-end test on **one machine with one Postgres server**: "A off" means A's services closed and A's database refusing connections, not a second machine.
- B has no HTTP endpoint of its own: an application embeds the gate.
- B's copy of A's list is in memory, so after a restart B refuses A's agents until the first poll succeeds. The replay guard is in memory too: correct for one B process.
- The publisher's development seed must move to KMS before real use (`CUSTOS_PUBLISHER_KEY_PROVIDER=kms`).
- Cross-domain key rotation is not designed: if A's key changes, B updates its anchor.

Sources: ADR 0014, ADR 0015, ADR 0016.

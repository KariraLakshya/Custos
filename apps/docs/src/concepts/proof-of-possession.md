# Proof of possession

A credential proves who an agent is. On its own it would be a **bearer credential**: whoever holds a copy could use it. Custos closes that gap by making every request for a token carry a fresh signature from the agent's own private key. This is called proof of possession.

## Agents hold their own keys

The agent's key pair is generated where the agent runs, by the CLI or SDK, and the private key never reaches Custos:

- The CLI writes it to `agent.key`, owner-only (mode `0600`, and an owner-only ACL on Windows), separate from the credential in `agent.json`. `register` refuses to overwrite an existing key file.
- The SDK returns it as `agent.secretKey` and leaves storing it to you.

Where the agent's key lives is the agent deployment's responsibility. Custos's obligations are never to receive it and to make the safe path the default. If the agent's machine is compromised, the attacker has the key and is the agent until it is revoked.

## What the proof contains

On every `POST /tokens`, the SDK builds a small signed envelope with:

| Field             | Meaning                                                                                 |
| ----------------- | --------------------------------------------------------------------------------------- |
| kind (`typ`)      | `custos-token-request-proof`, so a proof made for one purpose can't be used for another |
| audience (`aud`)  | The exact vault address it is for: `<VAULT_PUBLIC_URL>/tokens`                          |
| issued at (`iat`) | When it was made                                                                        |
| unique id (`jti`) | A random id, used once                                                                  |
| `tool`, `action`  | The one tool and action this request is for                                             |

It is signed with the agent's private key. The vault checks, and refuses on any failure:

1. The credential verifies against the trusted issuer.
2. The proof verifies against the public key **inside the credential**.
3. It is addressed to this vault (`WRONG_AUDIENCE` otherwise). Requests are signed for the exact address, so `localhost` and `127.0.0.1` count as different.
4. It was made within `VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS` of the vault's clock (60 by default, at most 300; `STALE` otherwise).
5. Its tool and action match the request (`WRONG_REQUEST` otherwise).
6. Its id has not been seen before (`REPLAYED`). The replay cache is in memory, bounded, and refuses new requests when full (`REPLAY_CACHE_FULL`) rather than forgetting old ones.

Each failure is answered `401 INVALID_PROOF_OF_POSSESSION` with the reason, which the CLI explains ([Refusal codes](/reference/refusals#reasons-under-invalid-proof-of-possession)).

The design follows the DPoP pattern (RFC 9449), encoded in Custos's own compact Ed25519 envelope rather than a JWT.

## What it does not cover

- **The tool call itself.** Proof of possession gates token issuance. The 60-second token is then a bearer token for its one tool and action ([Scoped tokens](/concepts/scoped-tokens)).
- **The request body.** The proof binds the tool and action, not the input. A request captured in flight could, within the skew window and before the real agent uses it, be spent once on the same tool and action with different input. The replay cache stops a second use. This is the same line DPoP draws, and it is an accepted risk (ADR 0015).

Registration uses the same construction with its own kind, `custos-registration-proof`, addressed to the identity service. Calls to another organisation use a third kind, `custos-foreign-call-proof` ([Federation](/concepts/federation)).

Sources: ADR 0007, ADR 0015.

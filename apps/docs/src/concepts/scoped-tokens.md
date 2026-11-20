# Scoped tokens

An agent never holds a long-lived key. When it wants to use a tool, it asks the vault for a **scoped token**: a pass valid for 60 seconds, for one agent, one tool and one action.

## The two requests behind one call

`custos use mock-database query`, or `connect(agent, "mock-database").call("query", ...)` in the SDK, makes two requests:

1. **`POST /tokens`** with the credential, the [proof of possession](/concepts/proof-of-possession), the tool and the action. The vault checks the credential, the proof, the revocation view and the agent's [grant](/concepts/policy-and-grants). If all pass, it returns a token.
2. **`POST /call`** with the token, the action and the input. This is the hot path: the vault checks the token's signature and expiry and the revocation view again, and then calls the tool.

The SDK asks for a fresh token for every call, so an agent never keeps anything longer-lived than one call.

## What a token is

A token is `base64url(claims).base64url(signature)`, signed by the vault with Ed25519. The claims are:

| Claim           | Meaning                                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `sub`           | The agent's DID                                                                                                          |
| `tool`          | The one tool it is for                                                                                                   |
| `action`        | The one action it is for                                                                                                 |
| `iat`, `exp`    | Issued at and expires at, in seconds. `exp` is 60 seconds after `iat`                                                    |
| `chain`, `dref` | Only on a delegated token: the agents in the chain, and a reference to its hand-off ([Delegation](/concepts/delegation)) |

There is no header and no algorithm field: there is one algorithm and one issuer, so there is nothing to negotiate. This avoids a class of JWT bugs (`alg: none`, algorithm confusion) and a JOSE library dependency (ADR 0003).

## What the vault checks on `/call`

- The signature, against the vault's own key.
- The expiry. The 60-second lifetime is fixed and is always checked; it cannot be configured off.
- The action matches the token (`ACTION_MISMATCH` otherwise).
- The revocation view says the agent (and, for a delegated token, every agent in its chain) is not revoked, and the view is fresh.

A token used after it expires is refused with `INVALID_TOKEN`; ask for a new one.

## Limits

- A token is a **bearer token** for its 60 seconds: proof of possession is checked when it is issued, not on each call. A stolen token works for up to 60 seconds, for its one tool and action.
- The vault's token key is in memory and changes when the vault restarts. That is safe because tokens live 60 seconds, but it is not in a KMS.

Sources: ADR 0003, ADR 0006, ADR 0007.

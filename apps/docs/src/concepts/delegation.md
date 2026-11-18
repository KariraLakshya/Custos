# Delegation

An agent often hands part of its work to a helper agent. Custos lets it pass on **part of its own access** with a signed **hand-off**, and records the whole chain of authority: which person or key granted the tool, which agent passed it on, and which agent finally acted. This is delegation provenance.

```bash
# As the first agent: let the helper run `query` on mock-database.
custos delegate mock-database query --to <helper id>

# As the helper:
custos use mock-database query --credential helper.json --key helper.key --delegation delegation.json
```

## A hand-off

A hand-off is a small envelope signed by the **delegating agent's own key**. Nothing is sent anywhere when it is made: Custos first sees it when the helper uses it. It names:

| Field               | Meaning                                                                  |
| ------------------- | ------------------------------------------------------------------------ |
| `iss`               | The delegating agent's DID                                               |
| `sub`               | The receiving agent's DID                                                |
| `grants`            | The tools, and the actions on each, being passed on                      |
| `depth`             | How many more times it may be passed on. Default 0: the receiver may not |
| `prev`              | The hash of the hand-off this one extends, or none for the first         |
| `iat`, `exp`, `jti` | When it was made, when it ends (default 10 minutes), and a unique id     |

A **delegation** (the `delegation.json` file) is the list of hand-offs from the first delegator down, plus each delegator's credential, so the vault can check every signature without fetching anything. It is not a secret: it is made out to one receiving agent, which must still prove it holds its own key.

## The rules: it only ever narrows

The vault checks the whole chain on `POST /tokens`, locally, with no network call:

- **The root is a real grant.** The first delegator must hold an operator's [grant](/concepts/policy-and-grants) for the tool, and that grant must record who made it. A grant with no "granted by" still works for the agent itself, but cannot be delegated.
- **Never wider.** Each hand-off passes on only tools and actions its delegator holds; the first is within the root grant.
- **Never longer.** Each hand-off ends no later than the one it extends, and lasts at most `DELEGATION_MAX_LIFETIME_SECONDS` (1 hour by default).
- **Depth shrinks.** Each hand-off allows fewer further hand-offs than its parent.
- **The links follow on.** Each hand-off's `iss` is the previous one's `sub`, and its `prev` is the previous one's hash, so a hand-off spliced in from another chain fails.
- **It ends at the caller.** The last hand-off is made out to the agent asking, whose key the proof of possession has just proven.
- **It covers this request.** The tool and action asked for are in the last hand-off.
- **Bounded size.** At most `DELEGATION_MAX_LINKS` hand-offs (3 by default) and `DELEGATION_MAX_BYTES` in total (16 KiB). These limits cannot be switched off.

The receiving agent needs no grant of its own. A refused chain is `403 DELEGATION_DENIED` with a reason, such as `NOT_COVERED` or `WIDENED` ([all reasons](/reference/refusals#reasons-under-delegation-denied)).

The SDK refuses to build a hand-off the vault would refuse anyway (widening, passing on a depth-0 delegation, extending one that has expired).

## Passing it on again

If a hand-off allows it (the first agent made it with `--depth 1` or more), the receiver can pass on part of it with `--extending`, signing as itself:

```bash
# As the helper:
custos delegate mock-database query --to <third agent id> --extending delegation.json \n  --credential helper.json --key helper.key --out delegation-2.json
```

## Revoking

- **Revoking any agent in a chain refuses every agent below it.** The token carries the chain, and the vault checks every agent in it on every call.
- **There is no way to cancel one hand-off** without revoking an agent. Hand-offs are short-lived instead.
- **Taking the tool back from the root agent** needs an ungrant, which doesn't exist yet; revoke the root agent.

## The record

The vault records a delegated token's issue once, with the full evidence: the chain of DIDs, the root's principal, the hand-offs and the credentials. Each call made with it names the chain. `custos audit-log` re-checks every chain offline against the identity service and prints it as "operator → agent → agent".

Sources: ADR 0020.

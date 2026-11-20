# Policy and grants

Custos **denies by default**. A registered agent can do nothing until an operator grants it a tool.

## Granting a tool

```bash
custos grant mock-database --to <agent id>
```

A grant is one row: this agent may use this tool, every action on it. It is stored by the vault (`POST /policies`, which needs an operator key with the `policies:write` scope) together with **who granted it**: the operator key's name, or the email of an operator signed in with SSO. That "granted by" is the root of any [delegation](/concepts/delegation) chain, and the grant itself is written to the audit log.

`--to` takes the agent's id or its DID. An id is turned into a DID under the identity service's DID (`--identity-issuer`, default `did:web:localhost%3A4001`). The older form, `--credential agent.json`, still works. You must give exactly one of the two: `grant` has no default agent, because an operator must say which agent gets the tool.

## Where it is checked

The grant is checked **once, when the agent asks for a token**, after its credential and proof of possession have verified. Checking it on every call would put a database read on the hot path. It doesn't need to be: a token is already bound to one tool and lives 60 seconds, so once issuance for an ungranted tool is refused there is nothing left to re-check (ADR 0006).

An ungranted tool is refused with `403 POLICY_DENIED`.

## Limits today

- **Tool level only.** A grant covers every action of the tool. Narrowing to particular actions happens only through [delegation](/concepts/delegation).
- **No way to take one grant back.** There is no ungrant endpoint yet. To stop an agent using a tool, [revoke](/concepts/revocation) the agent and register a new one with the right grants.
- **No policy language.** This is a simple allowlist of agent and tool, not a rules engine.
- **Grants can't be listed** through the API on `main`.

Sources: ADR 0006, ADR 0020 (granted by).

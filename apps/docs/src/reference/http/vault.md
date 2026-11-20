# Vault

Holds tool credentials, issues scoped tokens and makes tool calls. Default port 4002 (`PORT`). Source: `services/vault/src/server.ts`.

## `GET /health`

`200 { "status": "ok", "service": "vault" }`

## `POST /credentials`

Store a tool's credential, encrypted. **Scope:** `credentials:write` (operator).

```json
{ "tool": "stripe", "secret": "sk_test_..." }
```

`201 { "tool": "stripe" }`. The secret is never returned. `400 INVALID_INPUT` if either field is missing or empty. Audited with the principal (never the secret).

## `POST /policies`

Grant an agent a tool. **Scope:** `policies:write` (operator).

```json
{ "agentId": "did:web:localhost%3A4001:agents:3f2b8c1e-...", "tool": "mock-database" }
```

`agentId` is the agent's **DID**. `201 { "agentId": "...", "tool": "..." }`. The grant records who made it. There is no route to remove a grant.

## `GET /policies`

List grants. **Scope:** `policies:read` (operator). Optional query: `agent` (a DID), `limit`, `cursor`.

```json
{
  "grants": [
    {
      "agentDid": "did:web:localhost%3A4001:agents:3f2b8c1e-...",
      "tool": "mock-database",
      "grantedBy": {
        "kind": "operator",
        "id": "a6b2cc20050d6a5d",
        "name": "alice",
        "via": "custos-admin"
      },
      "createdAt": "2026-11-18T10:01:00.000Z"
    }
  ],
  "nextCursor": null
}
```

It never returns tool credentials. `grantedBy` is `null` for grants made before it was recorded. The cursor is opaque. Paged: up to `limit` items (1 to 200, default 50); pass the returned `nextCursor` as `cursor` for the next page (`null` on the last page). Unknown or repeated query parameters, a malformed value or a `limit` over 200 get `400 { "error": { "code": "INVALID_INPUT" } }`. Reads are not audited.

## `POST /tokens`

Ask for a 60-second scoped token. No API key: the agent is authenticated by its credential and proof of possession.

```json
{
  "tool": "mock-database",
  "action": "query",
  "credential": { "issuer": "did:web:localhost%3A4001", "...": "..." },
  "proof": "<token-request proof>",
  "delegation": { "handOffs": ["..."], "credentials": [{ "...": "..." }] }
}
```

| Field            | Rules                                                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `tool`, `action` | 1 to 128 characters each                                                                                                 |
| `credential`     | The agent's credential exactly as issued                                                                                 |
| `proof`          | Signed by the agent's key, addressed to `<VAULT_PUBLIC_URL>/tokens`, bound to this tool and action. 1 to 4096 characters |
| `delegation`     | Optional: a chain the agent acts under ([Delegation](/concepts/delegation))                                              |

`200 { "token": "..." }`.

| Status | Code                          | When                                                     |
| ------ | ----------------------------- | -------------------------------------------------------- |
| 400    | `INVALID_INPUT`               | The body doesn't match                                   |
| 401    | `INVALID_AGENT_CREDENTIAL`    | The credential doesn't verify, or is from another issuer |
| 401    | `INVALID_PROOF_OF_POSSESSION` | The proof fails; `reason` says why                       |
| 403    | `POLICY_DENIED`               | The agent has no grant for this tool                     |
| 403    | `AGENT_REVOKED`               | The agent, or an agent in its chain, is revoked          |
| 403    | `DELEGATION_DENIED`           | The chain is refused; `reason` says why                  |
| 404    | `UNKNOWN_TOOL`                | No credential is stored for this tool                    |
| 503    | `REVOCATION_STATE_STALE`      | The vault's revocation view is too old                   |
| 503    | `UNVERIFIABLE_ISSUER`         | The vault can't fetch the identity service's key         |
| 502    | e.g. `SIGNING_FAILED`         | Anything else                                            |

Refusals of an authenticated agent (not a bad credential or proof) are audited.

## `POST /call`

Use a token. This is the hot path.

```json
{ "token": "...", "action": "query", "input": { "table": "customers" } }
```

`200 { "result": ... }`, the tool's answer. Every outcome is audited.

| Status | Code                                                        | When                                                          |
| ------ | ----------------------------------------------------------- | ------------------------------------------------------------- |
| 400    | `INVALID_INPUT` / `UNKNOWN_ACTION`                          | Bad body, or the tool has no such action                      |
| 401    | `INVALID_TOKEN`                                             | Bad signature or expired                                      |
| 401    | `ACTION_MISMATCH`                                           | The token is for another action                               |
| 403    | `AGENT_REVOKED`                                             | The agent, or any agent in the token's chain, is revoked      |
| 503    | `REVOCATION_STATE_STALE` / `REVOCATION_STATE_UNKNOWN_AGENT` | The revocation view is too old, or hasn't recorded this agent |
| 502    | e.g. `UPSTREAM_ERROR`                                       | The tool answered with an error                               |

## `POST /revocations`

The push endpoint the revocation service sends signed tombstones to. No API key: the tombstone's signature, checked against the revocation service's DID document, is what is trusted.

```json
{ "tombstone": "<signed tombstone>" }
```

`202 { "revoked": "<agent DID>" }`. `401 INVALID_TOMBSTONE` if the signature doesn't verify; `502` if it can't be checked.

## `GET /revocations`

The vault's revocation view, for monitoring:

```json
{ "revokedCount": 1, "freshAsOf": "2026-11-18T10:00:05.000Z", "stale": false }
```

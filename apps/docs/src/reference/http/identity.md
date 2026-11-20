# Identity service

Registers agents and signs their credentials. Default port 4001 (`PORT`). Source: `services/identity/src/server.ts`.

## `GET /health`

`200 { "status": "ok", "service": "identity" }`

## `GET /.well-known/did.json`

The identity service's own DID document: the public key that verifies every agent credential it issued. Open.

## `POST /agents`

Register an agent. **Scope:** `agents:register` (operator).

Request:

```json
{
  "publicKey": "z6Mk...",
  "proof": "<registration proof>",
  "name": "billing-bot"
}
```

| Field       | Rules                                                                                          |
| ----------- | ---------------------------------------------------------------------------------------------- |
| `publicKey` | The agent's Ed25519 public key, multibase. 1 to 64 characters                                  |
| `proof`     | A registration proof signed by that key, addressed to this service's DID. 1 to 4096 characters |
| `name`      | Optional. 1 to 64 characters, `^[A-Za-z0-9][A-Za-z0-9 ._-]*$`                                  |

The SDK's `register()` builds the key and proof for you.

Response `201`:

```json
{
  "id": "3f2b8c1e-...",
  "did": "did:web:localhost%3A4001:agents:3f2b8c1e-...",
  "name": "billing-bot",
  "credential": { "...": "..." }
}
```

`name` is `null` when none was given. It is not in the credential.

| Status | Code                            | When                                                                               |
| ------ | ------------------------------- | ---------------------------------------------------------------------------------- |
| 400    | `INVALID_INPUT`                 | The body doesn't match, including a bad name (checked before anything is reserved) |
| 400    | `INVALID_PUBLIC_KEY`            | The public key isn't a valid key                                                   |
| 401    | `UNAUTHORIZED`                  | No usable key with `agents:register`                                               |
| 401    | `INVALID_REGISTRATION_PROOF`    | The proof doesn't verify, is for another audience, or is stale                     |
| 409    | `KEY_ALREADY_REGISTERED`        | An agent with this public key exists                                               |
| 502    | e.g. `STATUS_ALLOCATION_FAILED` | The revocation service couldn't reserve the agent's status bit, or signing failed  |

Each registration, and each refusal for a missing scope, is audited with the principal.

## `GET /agents`

List agents. **Scope:** `agents:read` (operator). Optional query: `id` (a UUID) **or** `did`, not both; `limit`; `cursor`.

```json
{
  "agents": [
    {
      "id": "3f2b8c1e-...",
      "did": "did:web:localhost%3A4001:agents:3f2b8c1e-...",
      "name": "billing-bot",
      "registeredAt": "2026-11-18T10:00:00.000Z",
      "registeredBy": {
        "kind": "operator",
        "id": "a6b2cc20050d6a5d",
        "name": "alice",
        "via": "custos-admin"
      }
    }
  ],
  "nextCursor": null
}
```

`name` is `null` for an agent registered without one. `registeredBy` is `null` for agents registered before this was recorded. An unknown `id` or `did` gives an empty list. Paged: up to `limit` items (1 to 200, default 50); pass the returned `nextCursor` as `cursor` for the next page (`null` on the last page). Unknown or repeated query parameters, a malformed value or a `limit` over 200 get `400 { "error": { "code": "INVALID_INPUT" } }`. Reads are not audited.

## `GET /agents/:id/did.json`

An agent's DID document. Open. No Custos verifier depends on it: the agent's key is also inside its credential.

| Status | Body                              | When                |
| ------ | --------------------------------- | ------------------- |
| 200    | The DID document                  |                     |
| 400    | `{ "error": "INVALID_AGENT_ID" }` | `:id` is not a UUID |
| 404    | `{ "error": "AGENT_NOT_FOUND" }`  | No such agent       |

## Operator sign-in routes

These exist only when SSO is configured ([how-to](/how-to/operator-sso)). They are deliberately unauthenticated: they are how an operator gets a key. Responses carry `cache-control: no-store`.

### `POST /operator/login`

Starts a sign-in. `201 { "loginId": "<32 hex>", "authorizationUrl": "https://..." }`, or `503 SSO_BUSY` when too many sign-ins are in progress.

### `GET /operator/callback`

Where the provider sends the browser back (`SSO_REDIRECT_URL`). Answers plain text: success, or `400` for an unknown sign-in, `401` for a failed one.

### `GET /operator/login/:loginId`

Polled by `custos login` until the sign-in finishes.

| Status | Body                                                                                     |
| ------ | ---------------------------------------------------------------------------------------- |
| 202    | `{ "status": "pending" }`                                                                |
| 200    | `{ "operatorKey": "custos_operator_...", "name": "<email>", "expiresAt": "<ISO time>" }` |
| 401    | `{ "error": { "code": "<reason>" } }`, such as `NO_MAPPED_GROUP` or `TOKEN_REJECTED`     |
| 404    | `UNKNOWN_LOGIN`                                                                          |
| 400    | `INVALID_INPUT`: `:loginId` is not 32 hex characters                                     |

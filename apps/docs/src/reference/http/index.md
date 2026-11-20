# HTTP API

Each Custos service is a small JSON-over-HTTP server (Fastify). Most developers use the [CLI](/reference/cli) or the [SDK](/reference/sdk) instead; this reference is for anyone calling the services directly. It is taken from each service's `src/server.ts`.

| Service    | Default address         | Page                                     |
| ---------- | ----------------------- | ---------------------------------------- |
| identity   | `http://localhost:4001` | [Identity](/reference/http/identity)     |
| vault      | `http://localhost:4002` | [Vault](/reference/http/vault)           |
| revocation | `http://localhost:4003` | [Revocation](/reference/http/revocation) |
| audit      | `http://localhost:4004` | [Audit](/reference/http/audit)           |

## Authentication

Routes marked with a **scope** need an API key holding it, sent as:

```http
Authorization: Bearer custos_operator_...
```

or, for service-to-service calls, a client certificate through Envoy ([Run with mTLS](/how-to/mtls)). A missing, wrong, revoked or expired key, or one without the scope, is always answered the same way:

```http
HTTP/1.1 401 Unauthorized

{ "error": { "code": "UNAUTHORIZED" } }
```

After 10 failures in 5 minutes from one source, that source is locked out for 15 minutes. See [Control-plane authentication](/concepts/control-plane-auth).

Routes without a scope are open: the DID documents, the status list, `GET /revocations` and the audit `GET /records` and `GET /seals/status`. The last three will need `revocations:read` or `audit:read` in a later step; sending a key to them today does no harm. Identity `GET /agents` and vault `GET /policies` need `agents:read` and `policies:read` now. The two agent routes on the vault (`/tokens`, `/call`) are authenticated by the agent's credential, proof of possession and token instead of an API key.

## Errors

A refusal carries a code, in one of two shapes:

```json
{ "error": "INVALID_INPUT" }
{ "error": { "code": "POLICY_DENIED", "reason": "...", "...": "..." } }
```

The SDK reads both. Every code is explained in [Refusal codes](/reference/refusals). A request body that fails validation is `400 INVALID_INPUT`. Bodies are limited to Fastify's default of 1 MiB, and several fields have tighter bounds, given on each page.

Every service also answers `GET /health` with `{ "status": "ok", "service": "<name>" }`.

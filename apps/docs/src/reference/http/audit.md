# Audit service

Keeps the audit log as a hash-chained, sealed ledger. Default port 4004 (`PORT`). Source: `services/audit/src/server.ts`.

## `GET /health`

`200 { "status": "ok", "service": "audit" }`

## `GET /.well-known/did.json`

The audit service's DID document: the key seals are signed with. Open. To check a seal key, don't trust this document alone (the service controls it): ask whoever runs the service.

## `GET /seals/status`

How far sealing and copying to the outside seal store have got, `sealStore` (`"configured"` or `"not configured"`), and the last copy error, if any. Open.

## `POST /records`

Append one entry. Called by the other services, fire-and-forget. **Scope:** `audit:write` (service only).

The body is an audit event (`auditEventSchema` in `packages/contracts`): the agent DID or a principal, tool, action, data categories, policy rule and decision, reason, and for delegated calls the authority chain and evidence. Each field is bounded. The caller is recorded as `reportedBy` from its authenticated key or certificate.

`201 { "stored": true }`. `400 INVALID_INPUT` if the event doesn't match.

## `GET /records`

The ledger and its newest seal, exactly as stored; nothing is signed on read. Open, with `access-control-allow-origin: *`.

| Query     | Meaning                                                                                                                      |
| --------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `agentId` | Optional: an agent DID. Other agents' entries are returned as `{ seq, payloadHash }` only, so the chain can still be checked |

`200 { "entries": [...], "seal": "<compact seal>" | null }`. Check it with `custos audit-log`, which also checks the outside seal store and the seal it remembered.

::: warning Open read
On `main`, anyone who can reach this route can read agent DIDs, tools, decisions and operators' names, which for SSO operators are email addresses.
:::

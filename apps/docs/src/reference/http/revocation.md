# Revocation service

Records revocations, pushes signed tombstones, and publishes the status list. Default port 4003 (`PORT`). Source: `services/revocation/src/server.ts`.

## `GET /health`

`200 { "status": "ok", "service": "revocation" }`, plus `published` (the merge's state) when the published-list merge is on.

## `GET /.well-known/did.json`

The revocation service's DID document: the key every tombstone and the status list are verified against. Open.

## `POST /agents`

Reserve an agent's bit in the status list. Called by the identity service during registration. **Scope:** `status:allocate` (service only).

```json
{ "agentId": "3f2b8c1e-...", "agentDid": "did:web:localhost%3A4001:agents:3f2b8c1e-..." }
```

`agentId` must be a UUID. `201 { "agentDid": "...", "statusListIndex": 42, "statusListCredential": "<list URL>" }`. Asking again for the same agent returns the same index. `502` if allocation fails.

## `POST /revocations`

Revoke an agent. **Scope:** `agents:revoke` (operator).

```json
{ "agentId": "3f2b8c1e-...", "reason": "compromised" }
```

`agentId` is the agent's id (a UUID), not its DID. `reason` is optional.

`200`:

```json
{
  "agentId": "3f2b8c1e-...",
  "agentDid": "did:web:localhost%3A4001:agents:3f2b8c1e-...",
  "statusListIndex": 42,
  "revokedAt": "2026-11-18T10:00:00.000Z",
  "alreadyRevoked": false,
  "broadcast": { "delivered": 1, "failed": [] }
}
```

`broadcast` says which subscribers (`REVOCATION_SUBSCRIBER_URLS`) received the tombstone straight away. `404 UNKNOWN_AGENT` if no such agent; `502` otherwise. This route is never held back by the published-list merge. Audited with the principal and reason.

## `GET /revocations`

Every signed tombstone, for a subscriber catching up and for the dashboard. Open, with `access-control-allow-origin: *` (each tombstone is independently verifiable).

`200 { "tombstones": ["..."], "asOf": "<ISO time>" }`. `503 PUBLISHED_STATE_UNKNOWN` while the published-list merge is on and unconfirmed or stale; `502` on failure.

## `GET /status/revocation`

The signed Bitstring Status List credential. Open. The vault resyncs from it; anyone can check a revocation with it and the DID document above. Its `ttl` is `REVOCATION_STATUS_TTL_MS`; an unchanged list's signature is reused for `REVOCATION_STATUS_REUSE_MS`.

`503 PUBLISHED_STATE_UNKNOWN` as above; `502` on failure.

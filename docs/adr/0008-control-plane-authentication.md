# 0008: Control-plane authentication — operators and services

**Status:** Accepted, 2026-10-02. All four decisions are accepted: agent registration requires an operator key (§3, `agents:register`); service-to-service authentication (§1, §3: `audit:write`, `status:allocate`); one shared `api_keys` table (§5); the audit log stays readable without a key for now (see "Decided later"). **Not yet implemented.** Phase 5b step 4 in `docs/build-plan.md`. Builds on the design discussion in Notion, "12 — Auth security review", and corrects it where noted.

## Context

Agents now prove who they are (ADR 0007). Nobody else does. Every write that isn't an agent's own token request is open to anyone who can reach the service:

| Endpoint                       | What an attacker can do today                                                                                                                                                  |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| vault `POST /credentials`      | Replace a stored tool secret (e.g. the Stripe key) with one they control, so the vault sends agents' calls to the attacker's account                                           |
| vault `POST /policies`         | Grant any agent, including one they registered, access to any tool                                                                                                             |
| revocation `POST /revocations` | Revoke any agent: a one-request denial of service                                                                                                                              |
| identity `POST /agents`        | Register unlimited agents (each with a key they really hold; ADR 0007 stops forged keys, not unwanted registrations)                                                           |
| audit `POST /records`          | **Insert fabricated audit records, which the audit service then signs as genuine.** This forges the evidence trail that the compliance positioning (CLAUDE.md §10) depends on. |
| revocation `POST /agents`      | Exhaust status-list indexes                                                                                                                                                    |

The last two weren't in the Notion review. They are service-to-service endpoints, not operator ones, but just as open.

Two endpoints stay as they are:

- The **vault's own `POST /revocations`** (the tombstone receiver) is already authenticated by the tombstone's signature, and must stay reachable by the revocation service (ADR 0005).
- **`/tokens` and `/call`** are agent endpoints, covered by ADR 0007.

Read endpoints (`GET /records`, `GET /revocations`, `GET /status/revocation`, DID documents) return signed or public data and stay open. Whether the audit log should be readable by anyone is a real question, raised under "Open" below, not decided here.

## Decision

### 1. Two kinds of non-agent caller, one interface

- **Operators:** people or automation administering Custos.
- **Services:** Custos components calling each other.

Both authenticate through one interface:

```ts
interface ControlPlaneAuthenticator {
  authenticate(request): Promise<Principal | null>;
}
type Principal = {
  kind: "operator" | "service";
  id: string; // stable, safe to log
  name: string; // human-readable, for audit
  scopes: ReadonlySet<Scope>;
};
```

Route handlers and audit logging only ever see a `Principal`, never how it was proven. API keys come first. mTLS and SSO become further implementations of the same interface (Notion design, unchanged), so adding them changes no route.

### 2. Agents are structurally separate

Agent endpoints (`/tokens`, `/call`) never accept a `Principal`, and control-plane endpoints never accept an agent credential. They use different credential shapes, different middleware and different storage. An agent key can never authorize an admin action, and an operator key can never act as an agent.

### 3. Scopes, checked per route, deny by default

| Scope               | Grants                                    |
| ------------------- | ----------------------------------------- |
| `credentials:write` | vault `POST /credentials`                 |
| `policies:write`    | vault `POST /policies`                    |
| `agents:revoke`     | revocation `POST /revocations`            |
| `agents:register`   | identity `POST /agents`                   |
| `audit:write`       | audit `POST /records` (services only)     |
| `status:allocate`   | revocation `POST /agents` (services only) |

Operator keys can't hold the two service-only scopes. A missing, wrong or expired key, or a missing scope, all return the **same** `401 { error: { code: "UNAUTHORIZED" } }`, so failures don't reveal which check failed.

### 4. API keys

- **Format:** `custos_<kind>_<id>_<secret>`, where `<secret>` is 32 random bytes in base64url. The fixed prefix lets secret scanners (Gitleaks, GitHub) recognise a leaked key. `<id>` lets the server find the record without scanning.
- **Stored as `SHA-256(secret)`**, compared in constant time (`crypto.timingSafeEqual`). **Correction to the Notion design**, which said argon2id or bcrypt: those slow hashes exist for guessable human passwords. These keys are 256 random bits and can't be brute-forced, so a slow hash would only add latency to every admin request, giving a denial-of-service lever. bcrypt would also add a native dependency. SHA-256 comes from `@noble/hashes`, which is already a dependency. This is the approach GitHub and Stripe tokens use.
- **Shown once, at creation.** Never stored, logged or retrievable afterwards.
- **Expiry is mandatory** (default 90 days). **Revocation** sets `revoked_at`. Both are checked on every request.
- **Storage:** one `api_keys` table: id, kind, name, scopes, secret hash, created_at, expires_at, revoked_at.

### 5. Where keys are checked

All four services share one Postgres today. They share one `api_keys` table through a new package, **`packages/control-plane-auth`**: the authenticator, the Fastify hook, the schema, and key creation. A key is looked up per request (one indexed query) on the cold path only. Control-plane calls are rare; nothing on the agent hot path changes (CLAUDE.md §3).

_Considered:_ signed tokens checked offline with no table read. Rejected for now: revocation of an operator key would then need its own push mechanism, which is far more machinery than a per-request lookup on infrequent endpoints.

### 6. Creating the first key: never over HTTP

There is no unauthenticated "create the first admin" endpoint; that would just move the hole. Keys are created by a local command that needs direct database access (`DATABASE_URL`), the same trust level as running migrations:

```bash
pnpm custos-admin key create --kind operator --name lakshya --scopes credentials:write,policies:write,agents:revoke,agents:register --expires-in 90d
```

The key is printed once. Each service is given its own `service` key (e.g. the vault holds one with `audit:write`) through an environment variable, and refuses to boot without one. The same command also lists keys and revokes them.

### 7. Every control-plane write is audited

The audit record gains a principal: `{ kind, id, name }` alongside the existing agent fields. Operator actions get `kind: "operator"` with no agent. Records written before this change keep working (the new columns are nullable). The existing writes, granted or denied, become attributable to who made them.

### 8. Brute-force protection

After 10 failed authentications from one source address within 5 minutes, that source is refused for 15 minutes. It's in memory per service, like the replay cache: correct for one instance each, with a shared store needed once services scale out. Failed attempts are logged by key **id** only, never the secret.

### 9. mTLS and SSO

Unchanged from the Notion design; each gets its own implementation PR later in step 4:

- **mTLS** is terminated at a reverse proxy (sample config shipped). It maps the client certificate's subject or SAN to a `Principal`. It suits **services** especially, replacing their API keys.
- **SSO** is OIDC through `openid-client`, never hand-rolled; it maps the ID-token `sub`/`email` to an operator `Principal`. SAML is not supported until a customer needs it.

Each needs its own dependency justification when built.

## Consequences

- Every write endpoint requires a key. **Breaking changes:**
  - SDK `register`/`grant`/`deprovision` and CLI `register`/`grant`/`deprovision` need an operator key: SDK `operatorKey` option, CLI `CUSTOS_OPERATOR_KEY` env var.
  - Agents' own `connect().call()` is unchanged.
  - The README gains one step: create an operator key.
- The vault, identity and revocation services each need a service key to reach audit and revocation, so the local walkthrough gains three environment variables. A single `pnpm custos-admin dev-keys` command will generate a development set for local use, so the README stays short.
- The services now share a table through a package. That's acceptable while they share a database, and recorded so it's revisited when they don't.
- The forged-audit-record hole closes. The audit trail becomes evidence of something.

## Decided 2026-10-02 (formerly open)

- **§5, one shared key table vs signed tokens:** shared table, as proposed. The founder confirmed it.
- **Audit-log read access:** `GET /records` stays readable without a key in step 4. It names agents and tools, but not data, and the live dashboard reads it from the browser. An `audit:read` scope is added when the dashboard gets operator login (SSO). For DPDP-style deployments it shouldn't stay public, so this is deferred, not dropped.

## Open (not decided here)

- **Open-source vs proprietary** is still undecided (`docs/state.md`). It affects how much the mTLS/SSO sample configs need to cover, not the design.

## Implementation notes

**Step 4, part 1: the API-key layer (2026-10-02).** Built, not yet wired into any route.

- `packages/control-plane-auth`: key format, generation and parsing (`api-key.ts`); scopes (`scopes.ts`); `ControlPlaneAuthenticator` and `createApiKeyAuthenticator` (`authenticator.ts`); the `api_keys` table and its store (`schema.ts`, `store.ts`); the lockout (`lockout.ts`); and a Fastify `requireScope` preHandler plus `principalOf(request)` (`fastify.ts`). Migration `0006`, which only adds the table; to reverse it, `DROP TABLE api_keys`.
- `apps/admin` (`pnpm custos-admin key create|list|revoke`) connects to the database directly. It is a separate app rather than part of `apps/cli`, because `apps/cli` talks to services over HTTP and never touches the database.
- **Deviation:** `authenticate` returns `Result<Principal, AuthenticationFailure>`, not `Principal | null`. Security paths return errors as values (CLAUDE.md §7), and the failure reason plus key id are needed for the log line. Neither ever reaches the response.
- A locked-out source gets the same `401 UNAUTHORIZED` as every other failure. Only authentication failures count towards the lockout; a valid key that lacks a scope does not.
- Scopes are checked twice: when a key is created, and again when it authenticates. So an `api_keys` row edited by hand still can't give an operator key a service-only scope.
- `@custos/observability` now redacts `authorization`.
- `.gitleaks.toml` has a `custos-api-key` rule. Gitleaks' default rules don't recognise the `custos_` prefix, which was verified: a real generated key passed a default-rules scan. The malformed-key test fixture `custos_operator_0123456789abcdef_` is allowlisted as an exact string.
- **Deferred to part 2 (the wiring):** `dev-keys`, because which service needs which scope is settled when the routes are wired. Also deferred: putting `requireScope` on each route, adding the principal to audit records, the SDK/CLI `operatorKey`, and the README.
- `request.ip` is the lockout's source key. Behind a reverse proxy it is the proxy's address unless Fastify's `trustProxy` is configured. This matters for the mTLS deployment and is noted there.

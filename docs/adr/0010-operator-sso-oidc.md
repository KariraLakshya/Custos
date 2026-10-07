# 0010: Operator single sign-on (OIDC), issuing short-lived operator sessions

**Status:** Accepted, 2026-10-07. Implements ADR 0008 §9 (SSO). The founder chose the browser-login flow with a short session, and Keycloak in Docker for tests and dev, then approved the design below.

## Context

Administrators (operators) authenticate today with API keys (ADR 0008): long-lived (90 days by default), created by `custos-admin`. A company wants its people to sign in with the company login, and wants access to end when someone leaves. The build plan's DONE check: SSO rejects tokens with a bad signature, issuer, audience or nonce, and expired ones, each proven in CI.

## Decision

### 1. An SSO login produces a short-lived operator key; nothing else changes

After a successful login, Custos creates an **operator API key** in the existing `api_keys` table:

- **Name:** the person's identity from the company login (e.g. `alice@acme.com`).
- **Scopes:** mapped from their company groups (§4).
- **Lifetime:** short (default 8 hours, configurable, capped).
- **Origin:** marked as created by SSO.

Everything already built then applies unchanged: the authenticator, scopes, the uniform 401, lockout, and revocation (`custos-admin key revoke`). Every admin action is audited with the person's name.

_Considered:_ verifying the company's ID token on every request. Rejected: ID tokens are meant for one login, not as API credentials, and expire in about an hour. It would also add a second authentication path to every service.

### 2. The identity service is the relying party, server-side

The login flow runs on the identity service, which already handles authentication for the platform. It uses the authorization-code flow with **PKCE, `state` and `nonce`**, as a **confidential client** with a client secret:

1. `custos login` calls `POST /operator/login` on identity. Identity creates a login transaction: random `state`, `nonce` and PKCE verifier, stored server-side for 5 minutes. It returns the company login URL and a one-time `loginId`.
2. The CLI opens that URL in the browser. The person signs in at the company's identity provider.
3. The provider redirects to identity's `GET /operator/callback`. Identity checks `state`, exchanges the code (secret + PKCE), and verifies the ID token with `openid-client`:
   - signature, against the provider's published keys (JWKS)
   - `iss`, `aud` and `azp`
   - `exp` and `iat`, with a small clock-skew allowance
   - `nonce` against this transaction
4. If it passes, identity creates the short-lived operator key (§1) and marks the transaction complete. The browser shows "signed in, return to your terminal".
5. The CLI, polling `GET /operator/login/:loginId`, receives the key **once**; the transaction is then deleted. The CLI stores the key in a 0600 file (default `~/.custos/operator.key`), like `agent.key`, never printed. `CUSTOS_OPERATOR_KEY` still works and takes precedence.

Login transactions live in memory: correct for one identity instance, like the replay cache. Several instances need a shared store.

### 3. `openid-client` (one new dependency, three packages)

`openid-client` 6.x, by panva, is an OpenID-certified relying-party library. It depends only on `jose` and `oauth4webapi`, by the same author, neither of which has dependencies. It is never hand-rolled (CLAUDE.md §4). It is used **only** in the identity service: other services, the SDK and core don't import it.

### 4. Groups become scopes, by configuration

The provider adds a `groups` claim to the ID token. Identity maps groups to operator scopes from configuration, for example `SSO_GROUP_SCOPES='{"custos-admins":["agents:register","agents:revoke","credentials:write","policies:write"],"custos-auditors":[]}'`. A person in no mapped group is **refused at login**, and no key is created. Service-only scopes can never be granted this way (`scopeAllowedFor`, as for keys). The provider is configured by issuer URL, client ID and client secret (`SSO_ISSUER`, `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`). SSO is optional: without these settings, `/operator/*` doesn't exist.

### 5. Keycloak for tests and dev

- A digest-pinned `quay.io/keycloak/keycloak:26.4` runs with a checked-in realm export: realm `custos`, a confidential client, a `groups` mapper, and two test users (an admin, and one in no group). It uses an **opt-in Compose profile `sso`**.
- The **integration test** does a real login against real Keycloak: it fetches the login page, posts the test user's credentials, and follows the redirect to identity's callback.
- The **negative cases** of the DONE check sign tokens with test keys and serve them as the provider's metadata and JWKS. A real provider won't hand out deliberately broken tokens, so this is the only way to exercise each failure:
  - bad signature (signed by an unknown key)
  - wrong issuer
  - wrong audience
  - wrong nonce
  - expired
- The test users' passwords are throwaway values in the realm file, for local Keycloak only.

## Consequences

- People sign in with their company account, and their access ends when the company disables them: at the latest when the 8-hour session expires, or at once via `custos-admin key revoke`.
- Admin actions in the audit log name a person, not just a key.
- API keys stay for automation, such as CI and scripts.
- A login transaction store and two routes are added to identity; the realm file and a Compose profile are added to `infra/`.
- Single logout (back-channel logout from the provider) isn't covered. The 8-hour cap bounds it.
- The dashboard's own login (and an `audit:read` scope, from ADR 0008's decision 3) is a separate later step, not part of this.

## Implementation notes (2026-10-08)

- **Signature check is explicit.** `openid-client` skips verifying the signature of an ID token from the token endpoint by default, relying on TLS (OIDC Core 3.1.3.7). The first negative test showed that a token signed by an **unknown key was accepted**. Custos therefore enables `enableNonRepudiationChecks` in `discoverProvider`, shared by boot and the tests, so every ID token is verified against the provider's JWKS. That matters especially because a local provider may be plain http.
- **Code:** `services/identity/src/sso/`:
  - `config.ts`: group mapping, strict; refuses unknown and service-only scopes.
  - `transactions.ts`: in-memory, 5-minute, bounded at 1,000 (when full, new logins are refused, not evicted); single-use `state`; a completed login is returned once.
  - `sso.ts`: the flow. The callback rebuilds the URL from the configured `SSO_REDIRECT_URL`, never the request's host.
  - `boot.ts`: discovery at boot, so a misconfiguration stops the start.
- **Routes:** `POST /operator/login`, `GET /operator/callback`, `GET /operator/login/:loginId`. All are `no-store`. The browser page never shows the key or any failure detail.
- **Keys and audit:** `api_keys.created_via` (`custos-admin` or `sso`; migration `0008`, additive). A login is audited as `operator.login`.
- **Config:** `SSO_*` are all set or none. An http issuer is allowed only for localhost, with `SSO_ALLOW_HTTP_ISSUER=true`. `SSO_SESSION_HOURS` defaults to 8, maximum 24.
- **CLI:** `custos login` writes `~/.custos/operator.key` (0600; `CUSTOS_OPERATOR_KEY_FILE` overrides). Operator commands use `CUSTOS_OPERATOR_KEY` first, then that file.
- **Proof:**
  - `sso.test.ts`, against an in-test provider signing with `node:crypto`: bad signature, wrong issuer, wrong audience, wrong nonce and expired tokens are each refused, with no key created; plus no mapped group, replayed `state`, unknown `state`, and the routes end to end.
  - `sso-keycloak.test.ts`, against real Keycloak: alice gets a working key with her four scopes; bob is refused; a wrong password never reaches Custos.
  - **Mutation:** a wrong client secret fails the Keycloak test.

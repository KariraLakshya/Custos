# Operator sign-in (SSO)

Instead of handing out operator keys, let administrators sign in with their company account through any OpenID Connect provider. Locally, Keycloak stands in for the company. Background: Control-plane authentication.

`pnpm demo` already does steps 1 and 2: `pnpm dev` starts Keycloak, and the demo gives identity these settings. Follow them by hand only for the one-service-per-terminal setup in `docs/getting-started.md` in the repository.

## 1. Start the provider

```bash
pnpm dev        # or, on its own: pnpm dev:sso
```

This starts Keycloak on `http://localhost:8180` in Docker, with a demo realm called `custos`. The image stack (`pnpm images:up`) runs its own on `http://localhost:8280`.

## 2. Start identity with SSO settings

Add these to identity's usual settings:

```bash
SSO_ISSUER=http://localhost:8180/realms/custos
SSO_ALLOW_HTTP_ISSUER=true                     # plain http is accepted only for localhost
SSO_CLIENT_ID=custos-identity
SSO_CLIENT_SECRET=custos-dev-sso-client-secret-not-for-production
SSO_REDIRECT_URL=http://localhost:4001/operator/callback
SSO_GROUP_SCOPES='{"custos-admins":["agents:register","agents:revoke","credentials:write","policies:write","audit:read","revocations:read","policies:read","agents:read"]}'
```

Give all of issuer, client id, client secret, redirect URL and group mapping, or none: without them the `/operator/*` routes don't exist.

- `SSO_GROUP_SCOPES` maps a company group to operator scopes. Only people in a listed group can sign in.
- `SSO_SESSION_HOURS` sets how long the issued key lasts: 8 by default, 1 to 24.
- `SSO_RETURN_URLS` (optional) is a JSON list of the exact addresses a dashboard sign-in may return to, for example `'["http://localhost:4005/login/done"]'`. See [Dashboard sign-in](#dashboard-sign-in).

## 3. Sign in

In your own terminal:

```bash
custos login
```

It opens the sign-in page in your browser (`--no-browser` prints the address instead). The demo user is `alice` with password `alice-dev-password`. When you finish, the terminal says:

```text
signed in as alice@... until <time>; operator key saved to ~/.custos/operator.key
Next: custos register
```

The key is saved owner-only and never printed. `register`, `grant`, `revoke` and `audit-log` use it whenever `CUSTOS_OPERATOR_KEY` isn't set. Use `--key-file` (or `CUSTOS_OPERATOR_KEY_FILE`) to keep it elsewhere.

The demo user `bob` is in no mapped group, so he is refused (`NO_MAPPED_GROUP`). Everything a signed-in operator does appears in the audit log under their email.

## Dashboard sign-in

The dashboard signs people in through the same flow, started with a `returnTo` address. Identity compares that address with `SSO_RETURN_URLS` character for character and refuses anything else (`RETURN_URL_NOT_ALLOWED`), so it is never an open redirect. Write each entry exactly as a browser prints it, with no query or fragment, over `https` (plain `http` only for `localhost`); otherwise identity refuses to start.

- The key a dashboard sign-in gets holds **only the read scopes** of the person's groups (`audit:read`, `revocations:read`, `policies:read`, `agents:read`), even for an administrator. A group with no read scope is refused (`NO_READ_SCOPE`).
- After the company login, identity sends the browser back to `returnTo?code=<one-time code>`. The dashboard's server exchanges that code for the key once, within a minute (`POST /operator/login/:loginId/release`). A wrong, reused or late code is refused (`INVALID_LOGIN_CODE`) and ends that sign-in.
- The dashboard's own sign-in pages come in a later step. Until then, a dashboard sign-in in the demo ends on a "not found" page.

## Ending a session

Disabling a person at the company does not end a key already issued; there is no back-channel logout. Revoke it:

```bash
pnpm custos-admin key list
pnpm custos-admin key revoke <id>
```

The demo realm's passwords and client secret are for local use only.

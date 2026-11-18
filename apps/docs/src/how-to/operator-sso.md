# Operator sign-in (SSO)

Instead of handing out operator keys, let administrators sign in with their company account through any OpenID Connect provider. Locally, Keycloak stands in for the company. Background: [Control-plane authentication](/concepts/control-plane-auth#operator-sign-in-sso).

This uses the one-service-per-terminal setup from the README; `pnpm demo` does not configure SSO.

## 1. Start the provider

```bash
pnpm dev:sso
```

This starts Keycloak on `http://localhost:8180` in Docker, with a demo realm called `custos`.

## 2. Start identity with SSO settings

Add these to identity's usual settings:

```bash
SSO_ISSUER=http://localhost:8180/realms/custos
SSO_ALLOW_HTTP_ISSUER=true                     # plain http is accepted only for localhost
SSO_CLIENT_ID=custos-identity
SSO_CLIENT_SECRET=custos-dev-sso-client-secret-not-for-production
SSO_REDIRECT_URL=http://localhost:4001/operator/callback
SSO_GROUP_SCOPES='{"custos-admins":["agents:register","agents:revoke","credentials:write","policies:write"]}'
```

Give all of issuer, client id, client secret, redirect URL and group mapping, or none: without them the `/operator/*` routes don't exist.

- `SSO_GROUP_SCOPES` maps a company group to operator scopes. Only people in a listed group can sign in.
- `SSO_SESSION_HOURS` sets how long the issued key lasts: 8 by default, 1 to 24.

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

The key is saved owner-only and never printed. `register`, `grant` and `revoke` use it whenever `CUSTOS_OPERATOR_KEY` isn't set. Use `--key-file` (or `CUSTOS_OPERATOR_KEY_FILE`) to keep it elsewhere.

The demo user `bob` is in no mapped group, so he is refused (`NO_MAPPED_GROUP`). Everything a signed-in operator does appears in the audit log under their email.

## Ending a session

Disabling a person at the company does not end a key already issued; there is no back-channel logout. Revoke it:

```bash
pnpm custos-admin key list
pnpm custos-admin key revoke <id>
```

The demo realm's passwords and client secret are for local use only.

Source: ADR 0010.

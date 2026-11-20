# Control-plane authentication

Agents prove who they are with their own keys. People and services that **administer** Custos (register agents, grant tools, revoke, store tool passwords, write audit entries) prove who they are in one of three ways: an **API key**, a **certificate** (mTLS), or a **company sign-in** (SSO) that issues a short-lived API key.

## API keys

A key looks like `custos_<kind>_<id>_<secret>`, where kind is `operator` or `service`. Custos stores only a SHA-256 hash of it and compares in constant time, so a copy of the database doesn't give anyone a working key. Each key is shown once, when it is created.

Keys are created and revoked with `custos-admin`, which talks to the database directly. There is deliberately no web endpoint for making keys.

```bash
pnpm -s custos-admin dev-keys                     # one operator key and three service keys, for development
pnpm custos-admin key create --kind operator --name alice --scopes agents:register,policies:write
pnpm custos-admin key list
pnpm custos-admin key revoke <id>
```

Callers send the key as `Authorization: Bearer <key>`. The CLI and SDK read the operator key from `CUSTOS_OPERATOR_KEY`, never from a command-line flag, so it stays out of shell history.

## Scopes

Each key carries scopes. Every control-plane write requires one, and so do the newer reads:

| Scope               | Allows                               | Route                                                      | Key kind     |
| ------------------- | ------------------------------------ | ---------------------------------------------------------- | ------------ |
| `agents:register`   | Registering an agent                 | identity `POST /agents`                                    | operator     |
| `policies:write`    | Granting a tool                      | vault `POST /policies`                                     | operator     |
| `credentials:write` | Storing a tool's credential          | vault `POST /credentials`                                  | operator     |
| `agents:revoke`     | Revoking an agent                    | revocation `POST /revocations`                             | operator     |
| `audit:write`       | Adding an audit entry                | audit `POST /records`                                      | service only |
| `status:allocate`   | Reserving an agent's status-list bit | revocation `POST /agents`                                  | service only |
| `agents:read`       | Listing agents                       | identity `GET /agents`                                     | operator     |
| `policies:read`     | Listing grants                       | vault `GET /policies`                                      | operator     |
| `audit:read`        | Reading the audit log                | audit `GET /records` (not yet enforced)                    | operator     |
| `revocations:read`  | Reading the revocation list          | revocation and vault `GET /revocations` (not yet enforced) | operator     |

Service-only scopes are refused on operator keys, both when a key is created and when it is used. The services' own keys: identity holds `status:allocate` and `audit:write`; the vault and revocation hold `audit:write`.

Every refusal is the same `401 UNAUTHORIZED`, whether the key is missing, wrong, revoked, expired or lacks the scope, so a caller learns nothing about why. After **10 failures in 5 minutes** from one address, that address is locked out for **15 minutes**. Every control-plane write is audited with the principal that made it, allowed or refused for a missing scope.

`GET /agents` and `GET /policies` need their read scope. The older reads (`/revocations`, audit `/records` and `/seals/status`) are still open; `audit:read` and `revocations:read` exist so callers can already send a key, and those reads close in a later step. The DID documents and the signed status list stay open on purpose, so anyone can verify a credential offline.

## Certificates (mTLS)

Instead of service keys, the services can prove who they are to each other with certificates, through an Envoy proxy. Envoy requires a client certificate from the Custos development certificate authority and allows only the expected services on each listener: identity may reach revocation; vault, identity and revocation may reach audit. Each certificate names its service as `spiffe://custos.local/service/<name>`, and that name is what the audit log records.

A service trusts Envoy's forwarded identity header only when the connection really comes from Envoy, checked by Envoy's own certificate. A forged header sent straight to a service is ignored. A service is given exactly one of a service key or a certificate, never both. See [Run with mTLS](/how-to/mtls).

## Operator sign-in (SSO)

Instead of handing out operator keys, administrators can sign in with their company account through any OpenID Connect provider. `custos login` opens the sign-in page; the identity service checks the login (with PKCE, a single-use state value, a nonce and signature checks) and issues a short-lived operator key, 8 hours by default and at most 24, named by the person's email. The key's scopes come from the person's company groups, mapped in `SSO_GROUP_SCOPES`; someone in no mapped group is refused.

The key is saved to `~/.custos/operator.key`, owner-only, and never printed. Operator commands use it whenever `CUSTOS_OPERATOR_KEY` isn't set. Disabling the person at the company doesn't end a key already issued; `custos-admin key revoke` does. See [Operator sign-in (SSO)](/how-to/operator-sso).

Sources: ADR 0008, ADR 0009, ADR 0010.

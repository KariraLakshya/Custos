# Optional setups

Ways to run Custos beyond the [README](../README.md) quickstart and [running it by hand](./getting-started.md): services proving who they are with certificates, administrators signing in with a company account, accepting another organisation's agents, and keeping signing keys in AWS KMS. Every setting is also listed in [`.env.example`](../.env.example).

## Optional: services authenticate to each other with certificates (mTLS)

Instead of service keys, Custos's services can prove who they are to each other with certificates, through an Envoy proxy (ADR 0009). Operators still use their operator key.

```bash
pnpm dev:mtls     # makes a dev certificate authority and certificates, then starts Envoy (Docker)
```

On Linux, run `export CUSTOS_ENVOY_USER=$(id -u):$(id -g)` first, so Envoy can read the keys the generator gave you. Then start each service with its certificate **instead of** its `*_SERVICE_KEY`, with `C=infra/mtls/certs` and `MTLS_CA=$C/ca.crt` set in every terminal:

| Service    | Settings (in addition to its usual ones)                                                                                                                                                                                                           |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| audit      | `AUDIT_MTLS_PORT=4014 AUDIT_MTLS_SERVER_CERT=$C/audit-server.crt AUDIT_MTLS_SERVER_KEY=$C/audit-server.key`                                                                                                                                        |
| revocation | `AUDIT_URL=https://localhost:5004 REVOCATION_MTLS_CERT=$C/revocation.crt REVOCATION_MTLS_KEY=$C/revocation.key REVOCATION_MTLS_PORT=4013 REVOCATION_MTLS_SERVER_CERT=$C/revocation-server.crt REVOCATION_MTLS_SERVER_KEY=$C/revocation-server.key` |
| identity   | `REVOCATION_URL=https://localhost:5003 AUDIT_URL=https://localhost:5004 IDENTITY_MTLS_CERT=$C/identity.crt IDENTITY_MTLS_KEY=$C/identity.key`                                                                                                      |
| vault      | `AUDIT_URL=https://localhost:5004 VAULT_MTLS_CERT=$C/vault.crt VAULT_MTLS_KEY=$C/vault.key`                                                                                                                                                        |

A service refuses to start if its certificate is for another service, has expired, or if it's given both a key and a certificate. The audit log then names each service by its certificate (`spiffe://custos.local/service/…`). The certificates and keys live in `infra/mtls/certs/`, which is gitignored.

## Optional: administrators sign in with a company account (SSO)

Instead of handing out operator keys, administrators can sign in with their company login, through any OpenID Connect provider (ADR 0010). Locally, Keycloak stands in for the company:

```bash
pnpm dev:sso      # starts Keycloak on http://localhost:8180 (Docker) with a demo realm
```

Start identity with these settings, as well as its usual ones:

```bash
SSO_ISSUER=http://localhost:8180/realms/custos
SSO_ALLOW_HTTP_ISSUER=true                     # plain http is accepted only for localhost
SSO_CLIENT_ID=custos-identity
SSO_CLIENT_SECRET=custos-dev-sso-client-secret-not-for-production
SSO_REDIRECT_URL=http://localhost:4001/operator/callback
SSO_GROUP_SCOPES='{"custos-admins":["agents:register","agents:revoke","credentials:write","policies:write","audit:read","revocations:read","policies:read","agents:read"]}'
```

Then, in your own terminal:

```bash
custos login      # opens the sign-in page; demo user alice / alice-dev-password
```

`custos login` saves a key that lasts 8 hours (`SSO_SESSION_HOURS`) to `~/.custos/operator.key`, owner-only, and never prints it. `register`, `grant`, `revoke` and `audit-log` use it whenever `CUSTOS_OPERATOR_KEY` isn't set. Only people in a group listed in `SSO_GROUP_SCOPES` can sign in: the demo user `bob` is in none, so he's refused. Everything they do appears in the audit log under their email. The demo realm's passwords and client secret are for local use only.

## Optional: trust another organisation's agents (federation)

Organisation B can accept agents that organisation A issued without ever calling A, even while A is switched off (ADR 0014). Three pieces:

- **A's publisher.** `custos-admin publish-status` runs on A's security operator's machine. It signs A's list of revoked agents and writes it to a file that any static host serves (a bucket, a CDN). Revoking works with all of A's services off. The seed is A's revocation signing seed, from the environment only:

  ```bash
  CUSTOS_PUBLISHER_SIGNING_SEED=<A's REVOCATION_SIGNING_SEED> pnpm -s custos-admin publish-status revoke \
    --domain <A's revocation domain> --dir ./publisher --out ./site/status.json --validity-seconds 3600 \
    --credential agent.json --identity-did <A's identity DID> --identity-public-key <its key, from /.well-known/did.json> \
    --operator <your name> --reason <why>
  ```

  The first publish needs `publish-status init` with the same `--domain`, `--dir`, `--out` and `--validity-seconds`; `pnpm -s custos-admin publish-status --help` lists every option. The signing key is a development seed for now and must move to KMS before real use.

- **B's trust anchor.** B writes down A's two public keys and the list's address once, out of band (`parseTrustAnchors` in `@custos/federation`).
- **B's gate.** `createStatusCache` keeps a verified copy of A's list, fetched only from the configured address, and `createForeignAgentGate` checks each call: A's signature on the credential, the caller's proof that it holds the agent's key and that the proof was made for this very tool and action (pass them from your own routing, never from the caller; ADR 0015), and A's list. The answer is allowed, `401 UNAUTHORIZED` (the same for every bad credential or proof), `403 AGENT_REVOKED`, or `503 UNAVAILABLE` when B cannot confirm a recent list. A 503 still refuses. Allows and refusals of genuine agents are written to B's own audit log.

To watch it live, with the dashboard:

```bash
pnpm demo:federation
```

It starts A's identity and revocation services, B's audit service and the dashboard (ports 4001, 4003, 4004, 4005, plus 4006 for the list's file host), registers two agents at A and has them call B every few seconds. Open http://localhost:4005: the "Across organisations" panel shows B's decisions. Press Enter to switch A off (the agents keep working), Enter again to fire agent 1 through A's publisher (B refuses it, with a toast, while agent 2 carries on), and Enter or Ctrl-C to stop. In this demo A's database stays up, because B's audit service shares it; the test below switches it off too.

To see the whole story run as a test (two databases, A's real identity and revocation services, a static host, B's audit service):

```bash
pnpm --filter @custos/admin test:e2e
```

It registers two agents at A, has B accept them, stops A's services and makes A's database refuse connections, and has B accept them again. It then revokes one through the publisher (B refuses it within one poll), takes the host away until the list goes stale (B refuses both), and publishes again (B lets the other back in). Both organisations share one Postgres server and one machine in this run. B has no HTTP endpoint of its own yet: an application embeds the gate.

## Using AWS KMS for the issuer key

In production the identity service signs credentials with an AWS KMS key instead of a seed. The private key is created inside KMS and can never be read out.

1. Create an Ed25519 signing key:

   ```bash
   aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY --description "Custos issuer key"
   ```

2. Give the identity service's AWS identity `kms:GetPublicKey` and `kms:Sign` on that key, and nothing else.
3. Start identity with it. AWS region and credentials come from the standard AWS configuration (`AWS_REGION`, `AWS_PROFILE`, instance role, and so on):

   ```bash
   export IDENTITY_KEY_PROVIDER=kms
   export IDENTITY_ISSUER_KMS_KEY_ID=<key id or ARN>
   pnpm --filter @custos/identity start
   ```

Identity reads the key at boot and refuses to start if it can't, so a wrong key ID or missing permission shows up straight away, not at the first registration.

To check a key end to end (real KMS signatures verified by Custos's own code; creates nothing):

```bash
CUSTOS_TEST_KMS_KEY_ID=<key id or ARN> pnpm --filter @custos/kms test:kms
```

## Using AWS KMS for the audit key

The audit service seals its ledger with its own key (ADR 0017), a separate key again. Create it the same way, give the audit service's AWS identity `kms:GetPublicKey` and `kms:Sign` on it, and start the service with `AUDIT_KEY_PROVIDER=kms` and `AUDIT_SIGNING_KMS_KEY_ID=<key id or ARN>`. It signs at most one seal every `AUDIT_SEAL_INTERVAL_MS` (default 10 s), however busy the log is; recording an entry never calls KMS.

## Using AWS KMS for the revocation key

The revocation service signs every revocation notice and its status list. In production that key lives in KMS too ([ADR 0016](./adr/0016-revocation-signing-key-in-kms.md)). It is a separate key from the issuer key. Create it the same way, give the revocation service's AWS identity `kms:GetPublicKey` and `kms:Sign` on it, and start the service with:

```bash
export REVOCATION_KEY_PROVIDER=kms
export REVOCATION_SIGNING_KMS_KEY_ID=<key id or ARN>
pnpm --filter @custos/revocation start
```

The cross-company publisher (`custos-admin publish-status`) signs as the revocation service, so it uses **the same key**. Give the operator's AWS identity `kms:GetPublicKey` and `kms:Sign` on it, then:

```bash
export CUSTOS_PUBLISHER_KEY_PROVIDER=kms
export CUSTOS_PUBLISHER_KMS_KEY_ID=<the same key id or ARN>
```

The revocation service reuses a signed status list for `REVOCATION_STATUS_REUSE_MS` (default 5 s) while it hasn't changed, so anonymous requests can't each cost a KMS signature. A new revocation is signed straight away.

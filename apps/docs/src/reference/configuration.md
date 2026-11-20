# Configuration

Every service reads its settings from environment variables and **refuses to start** if one is invalid, rather than failing at the first request. Each service's schema is in its `src/env.ts`; the shared part is in `packages/config`. `.env.example` lists the development values.

Settings with no default are required. "Seed" and "key" values are secrets: keep them out of logs and version control.

## Every service

| Variable       | Default                                                                | Meaning                                              |
| -------------- | ---------------------------------------------------------------------- | ---------------------------------------------------- |
| `NODE_ENV`     | `development`                                                          | `development`, `test` or `production`                |
| `LOG_LEVEL`    | `info`                                                                 | `fatal`, `error`, `warn`, `info`, `debug` or `trace` |
| `PORT`         | 4001 identity, 4002 vault, 4003 revocation, 4004 audit, 4005 dashboard | Port to listen on                                    |
| `DATABASE_URL` | `postgres://custos:custos@localhost:5433/custos`                       | Postgres (not used by the dashboard)                 |

## Identity

| Variable                                                                                   | Default                 | Meaning                                                                                                           |
| ------------------------------------------------------------------------------------------ | ----------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `IDENTITY_DID_DOMAIN`                                                                      | `localhost:4001`        | Domain the service's and agents' `did:web` documents are published under                                          |
| `REVOCATION_URL`                                                                           | `http://localhost:4003` | Where agents' status bits are reserved. Registration fails if it is unreachable                                   |
| `AUDIT_URL`                                                                                | `http://localhost:4004` | Where control-plane writes are reported                                                                           |
| `IDENTITY_SERVICE_KEY`                                                                     |                         | This service's `custos_service_` key (`status:allocate`, `audit:write`). Exactly one of this or the mTLS settings |
| `IDENTITY_MTLS_CERT`, `IDENTITY_MTLS_KEY`, `MTLS_CA`                                       |                         | Client certificate, key and CA, instead of the service key ([mTLS](/how-to/mtls))                                 |
| `IDENTITY_KEY_PROVIDER`                                                                    | `local`                 | Where the issuer key lives: `local` or `kms`                                                                      |
| `IDENTITY_ISSUER_SEED`                                                                     |                         | 64 hex characters. Required for `local`. Keep it: a new seed invalidates every credential                         |
| `IDENTITY_ISSUER_KMS_KEY_ID`                                                               |                         | KMS key id or ARN. Required for `kms`                                                                             |
| `IDENTITY_REGISTRATION_PROOF_MAX_SKEW_SECONDS`                                             | 60                      | How old a registration proof may be                                                                               |
| `SSO_ISSUER`, `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_REDIRECT_URL`, `SSO_GROUP_SCOPES` |                         | Operator SSO: all or none. `SSO_GROUP_SCOPES` is JSON, group → scopes ([SSO](/how-to/operator-sso))               |
| `SSO_SESSION_HOURS`                                                                        | 8                       | Lifetime of a login's operator key, 1 to 24                                                                       |
| `SSO_ALLOW_HTTP_ISSUER`                                                                    | `false`                 | Allow a plain-http issuer, for a local provider only                                                              |

## Vault

| Variable                                       | Default                    | Meaning                                                                                                |
| ---------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------ |
| `VAULT_MASTER_KEY`                             |                            | **Required.** 64 hex characters: encrypts stored tool credentials. Keep it, or they can't be decrypted |
| `VAULT_PUBLIC_URL`                             | `http://localhost:4002`    | The vault's address as agents reach it. Proofs must be addressed to `<this>/tokens`                    |
| `VAULT_TRUSTED_ISSUER_DID`                     | `did:web:localhost%3A4001` | The one identity service whose credentials are accepted                                                |
| `VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS`           | 60                         | How old a token-request proof may be; at most 300. Also a delegation chain's clock skew                |
| `REVOCATION_URL`                               | `http://localhost:4003`    | Where the status list is fetched for resync                                                            |
| `REVOCATION_ISSUER_DID`                        | `did:web:localhost%3A4003` | The revocation service's DID; must match its `REVOCATION_DID_DOMAIN`                                   |
| `REVOCATION_MAX_STALENESS_MS`                  | 30000                      | After this long without a successful refresh, every call is refused                                    |
| `REVOCATION_RESYNC_INTERVAL_MS`                | 10000                      | How often the status list is fetched                                                                   |
| `REVOCATION_LIST_MAX_CLOCK_SKEW_SECONDS`       | 5                          | How far the revocation service's clock may differ                                                      |
| `DELEGATION_MAX_LINKS`                         | 3                          | Most hand-offs in one chain; at most 15                                                                |
| `DELEGATION_MAX_LIFETIME_SECONDS`              | 3600                       | Longest a hand-off may live; at most 86400                                                             |
| `DELEGATION_MAX_BYTES`                         | 16384                      | Largest chain, hand-offs and credentials together; at most 262144                                      |
| `AUDIT_URL`                                    | `http://localhost:4004`    | Where outcomes are reported                                                                            |
| `VAULT_SERVICE_KEY`                            |                            | This service's `custos_service_` key (`audit:write`). Exactly one of this or the mTLS settings         |
| `VAULT_MTLS_CERT`, `VAULT_MTLS_KEY`, `MTLS_CA` |                            | Client certificate, key and CA, instead of the service key                                             |

## Revocation

| Variable                                                                            | Default                 | Meaning                                                                                          |
| ----------------------------------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------ |
| `REVOCATION_DID_DOMAIN`                                                             | `localhost:4003`        | Domain this service's `did:web` document is published under                                      |
| `REVOCATION_KEY_PROVIDER`                                                           | `local`                 | Where the signing key lives: `local` or `kms`                                                    |
| `REVOCATION_SIGNING_SEED`                                                           |                         | 64 hex characters. Required for `local`. Keep it across restarts                                 |
| `REVOCATION_SIGNING_KMS_KEY_ID`                                                     |                         | KMS key id or ARN. Required for `kms`                                                            |
| `REVOCATION_SUBSCRIBER_URLS`                                                        | `http://localhost:4002` | Comma-separated vault URLs tombstones are pushed to. Empty turns the push off                    |
| `REVOCATION_STATUS_TTL_MS`                                                          | 30000                   | The status list's published `ttl`                                                                |
| `REVOCATION_STATUS_REUSE_MS`                                                        | 5000                    | How long an unchanged list's signature is reused. Keep it well below the vault's staleness bound |
| `REVOCATION_PUBLISHED_LIST_URL`                                                     |                         | Merge a publisher's list ([Federation](/how-to/federation)). Unset: off                          |
| `REVOCATION_PUBLISHED_MAX_AGE_SECONDS`, `REVOCATION_PUBLISHED_POLL_SECONDS`         |                         | Required when the URL is set, no defaults                                                        |
| `REVOCATION_PUBLISHED_MAX_CLOCK_SKEW_SECONDS`                                       | 5                       | How far the publisher's clock may be ahead                                                       |
| `AUDIT_URL`                                                                         | `http://localhost:4004` | Where revocations and allocations are reported                                                   |
| `REVOCATION_SERVICE_KEY`                                                            |                         | This service's `custos_service_` key (`audit:write`). Exactly one of this or the mTLS settings   |
| `REVOCATION_MTLS_CERT`, `REVOCATION_MTLS_KEY`, `MTLS_CA`                            |                         | Client certificate, key and CA, instead of the service key                                       |
| `REVOCATION_MTLS_PORT`, `REVOCATION_MTLS_SERVER_CERT`, `REVOCATION_MTLS_SERVER_KEY` |                         | An Envoy-only TLS listener: all three, plus `MTLS_CA`, or none                                   |

## Audit

| Variable                                                                        | Default          | Meaning                                                                                                  |
| ------------------------------------------------------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------- |
| `AUDIT_DID_DOMAIN`                                                              | `localhost:4004` | Domain this service's `did:web` document is published under                                              |
| `AUDIT_KEY_PROVIDER`                                                            | `local`          | Where the seal key lives: `local` or `kms`                                                               |
| `AUDIT_SIGNING_SEED`                                                            |                  | 64 hex characters. Required for `local`. Keep it: a new seed is a new key                                |
| `AUDIT_SIGNING_KMS_KEY_ID`                                                      |                  | KMS key id or ARN. Required for `kms`                                                                    |
| `AUDIT_SEAL_INTERVAL_MS`                                                        | 10000            | How often the head of the ledger is sealed, when it has moved                                            |
| `AUDIT_SEAL_STORE_URL`                                                          |                  | Outside seal store, as its insert-only user: `postgres://…` or `s3://<bucket>`. Unset: nothing is copied |
| `AUDIT_MTLS_PORT`, `AUDIT_MTLS_SERVER_CERT`, `AUDIT_MTLS_SERVER_KEY`, `MTLS_CA` |                  | An Envoy-only TLS listener: all, or none                                                                 |

The audit service calls no other Custos service, so it has no service key.

## The CLI and tools

| Variable                                                       | Used by                              | Meaning                                                                |
| -------------------------------------------------------------- | ------------------------------------ | ---------------------------------------------------------------------- |
| `CUSTOS_OPERATOR_KEY`                                          | `custos`, `vault seed`               | Operator key for `register`, `grant`, `revoke` and storing credentials |
| `CUSTOS_OPERATOR_KEY_FILE`                                     | `custos`                             | Where `custos login` keeps its key; default `~/.custos/operator.key`   |
| `CUSTOS_AUDIT_SEAL_STORE_URL`                                  | `custos audit-log`                   | The outside seal store, as its read-only user                          |
| `VAULT_URL`                                                    | `pnpm --filter @custos/vault seed`   | Vault address; default `http://localhost:4002`                         |
| `DATABASE_URL`                                                 | `custos-admin`                       | The database keys are created in                                       |
| `CUSTOS_PUBLISHER_SIGNING_SEED`                                | `custos-admin publish-status`        | Development signing seed (A's `REVOCATION_SIGNING_SEED`)               |
| `CUSTOS_PUBLISHER_KEY_PROVIDER`, `CUSTOS_PUBLISHER_KMS_KEY_ID` | `custos-admin publish-status`        | `kms` and the revocation service's KMS key                             |
| `CUSTOS_TEST_KMS_KEY_ID`                                       | `pnpm --filter @custos/kms test:kms` | A KMS key to check end to end                                          |
| `CUSTOS_ENVOY_USER`                                            | `pnpm dev:mtls` (Linux)              | `uid:gid` Envoy runs as, so it can read the keys                       |
| `AWS_REGION`, `AWS_PROFILE`, …                                 | KMS and S3                           | The standard AWS settings                                              |

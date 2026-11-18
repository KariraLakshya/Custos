# Run with mTLS

By default Custos services authenticate to each other with service API keys. This guide switches them to **certificates** instead, through an Envoy proxy, so each service proves who it is with a private key that never leaves its machine. Operators still use their operator key. Background: [Control-plane authentication](/concepts/control-plane-auth#certificates-mtls).

This uses the one-service-per-terminal setup from the README, not `pnpm demo`.

## 1. Make the certificates and start Envoy

On Linux, first let Envoy read the keys the generator gives you:

```bash
export CUSTOS_ENVOY_USER=$(id -u):$(id -g)
```

Then:

```bash
pnpm dev:mtls
```

This creates a development certificate authority, a server certificate for Envoy, and one client certificate per service (`infra/mtls/certs/`, gitignored), renders the Envoy configuration, and starts Envoy in Docker. The certificates are generated inside a pinned Alpine container with OpenSSL, so no npm dependency is involved. `pnpm mtls:certs` and `pnpm mtls:config` run the two halves separately.

Envoy listens on:

| Port | Forwards to       | Who may connect             |
| ---- | ----------------- | --------------------------- |
| 5003 | revocation (4013) | identity                    |
| 5004 | audit (4014)      | vault, identity, revocation |

## 2. Start each service with its certificate

In **every** service terminal set:

```bash
C=infra/mtls/certs
export MTLS_CA=$C/ca.crt
```

Then start each service with these settings **instead of** its `*_SERVICE_KEY`, in addition to its usual seed or key:

| Service    | Settings                                                                                                                                                                                                                                           |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| audit      | `AUDIT_MTLS_PORT=4014 AUDIT_MTLS_SERVER_CERT=$C/audit-server.crt AUDIT_MTLS_SERVER_KEY=$C/audit-server.key`                                                                                                                                        |
| revocation | `AUDIT_URL=https://localhost:5004 REVOCATION_MTLS_CERT=$C/revocation.crt REVOCATION_MTLS_KEY=$C/revocation.key REVOCATION_MTLS_PORT=4013 REVOCATION_MTLS_SERVER_CERT=$C/revocation-server.crt REVOCATION_MTLS_SERVER_KEY=$C/revocation-server.key` |
| identity   | `REVOCATION_URL=https://localhost:5003 AUDIT_URL=https://localhost:5004 IDENTITY_MTLS_CERT=$C/identity.crt IDENTITY_MTLS_KEY=$C/identity.key`                                                                                                      |
| vault      | `AUDIT_URL=https://localhost:5004 VAULT_MTLS_CERT=$C/vault.crt VAULT_MTLS_KEY=$C/vault.key`                                                                                                                                                        |

- `*_MTLS_CERT` and `*_MTLS_KEY` are the service's **client** certificate, for its calls out.
- `*_MTLS_PORT`, `*_MTLS_SERVER_CERT` and `*_MTLS_SERVER_KEY` open a second, TLS-only listener that accepts only Envoy. Give all three or none.
- The target URLs point at Envoy's `https://` listeners.

## 3. Check it

A service refuses to start if its certificate is for another service, has expired, or if it is given both a key and a certificate. Once running, `custos audit-log` names each reporting service by its certificate (`spiffe://custos.local/service/vault`, and so on) rather than by a key name.

## Limits

- The certificate authority is generated locally and has no revocation list; short certificate lifetimes bound the risk.
- The certificates are valid from one hour before generation, to allow for clock differences between Docker and the host.

Source: ADR 0009.

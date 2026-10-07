# 0009: mTLS through Envoy, with certificates made by openssl in Docker

**Status:** Accepted, 2026-10-03. Refines ADR 0008 §9. Part A (the proxy, certificates and proxy tests) and part B (services using it) are implemented. Part B replaced the planned trusted-address check with Envoy authenticating itself to the services (§7).

## Context

ADR 0008 §9 says mTLS is terminated at a reverse proxy and suits Custos services calling each other, replacing their API keys. It didn't pick the proxy or say how certificates are made. Two choices were open:

- **Where mTLS is checked.** In each service (Node's own TLS) or at a proxy. The founder chose the proxy, as ADR 0008 says.
- **Which proxy.** nginx or Envoy.
- **How certificates are made**, for tests (expired, wrong-CA, self-signed and wrong-name certificates must be proven to fail) and for local dev. Options: an npm library (`@peculiar/x509`), openssl run in Docker, or certificate files committed to the repo.

## Decision

### 1. Envoy is the proxy

Envoy over nginx, for security:

- **Name checking at the proxy.** Envoy can require a specific certificate name (SAN) per listener (`match_typed_subject_alt_names`). Open-source nginx has no SAN variable, so it could only check the deprecated CN field, or pass the whole certificate on for Custos to parse.
- **Safe identity forwarding.** In a proxy design, the realistic attack is a forged "who is calling" header. Envoy's `forward_client_cert_details: SANITIZE_SET` always strips any incoming `x-forwarded-client-cert` header and sets its own from the verified certificate. With nginx this is hand-written per route.
- **Direction.** The target architecture already plans Envoy sidecars, so this carries forward.

The cost is a larger, more complex codebase than nginx. Only Envoy's TLS and header features are used here, not service mesh.

### 2. Certificates come from openssl, in a pinned container

`infra/mtls/certs.mjs` runs `gen-certs.sh` inside `alpine:3.22`, pinned by digest, with `openssl` from Alpine's signed package repository (3.5.x at the time of writing; expired certificates need 3.4 or later).

- **No new npm dependency.** `@peculiar/x509` would have added about 7 packages to `custos-admin`, which runs with direct database access. A compromised package there could read or write `api_keys`. openssl adds none of that npm supply chain, and is the most heavily audited crypto toolkit available.
- **No private keys in the repo.** Committed fixtures would put keys in git history, need a secret-scanner exemption, and hold a time bomb: the "valid" certificates would expire one day and break CI.
- Docker is already required by `pnpm dev` and `pnpm test`, so this adds no new requirement.

### 3. Certificate names are SPIFFE-style URIs

Each Custos service gets a client certificate whose SAN is `spiffe://custos.local/service/<name>`, signed by one Custos CA, using ECDSA P-256 keys. Envoy has its own server certificate for `localhost`.

### 4. Each listener allows only the services that may call it

| Envoy listener (dev port) | In front of     | Allowed callers             | Why                                   |
| ------------------------- | --------------- | --------------------------- | ------------------------------------- |
| `revocation_mtls` (5003)  | revocation 4003 | identity                    | only identity reserves status slots   |
| `audit_mtls` (5004)       | audit 4004      | vault, identity, revocation | the services that write audit records |

A genuine certificate for the wrong service is refused at the proxy, in addition to the scope check the service itself makes.

### 5. Private keys stay owner-only

The generator runs as root (apk needs it), then hands the files back:

- On Linux, everything goes to the calling user, and Envoy runs as that user.
- On Docker Desktop, Envoy's image runs as uid 101, so `envoy.key` is given to uid 101.

The keys stay at `0600` throughout. Envoy never runs as root, and permissions are never loosened. Generated certificates and keys live under the gitignored `infra/mtls/certs/`.

### 6. One template, rendered for dev and tests

`envoy.yaml.tmpl` is rendered by `render-envoy.mjs` with dev ports, or the tests' ports. The tests therefore prove the real config, not a copy of it. `dns_lookup_family: V4_PREFERRED` is set because `host.docker.internal` can resolve to an IPv6 address a container has no route to.

## Consequences

- **The proof** is `packages/control-plane-auth/src/mtls-proxy.test.ts`, run against the real Envoy image, real generated certificates and real TLS. A valid certificate passes, and the service is told who called. A forged identity header is replaced. Each bad case is refused with its specific TLS alert, and nothing reaches the service:

  | Certificate                                             | Alert                |
  | ------------------------------------------------------- | -------------------- |
  | none                                                    | certificate required |
  | expired                                                 | certificate expired  |
  | other CA, self-signed                                   | unknown CA           |
  | wrong name, or genuine but not allowed on this listener | certificate unknown  |

  Removing the SAN allowlist, or setting `FORWARD_ONLY` instead of `SANITIZE_SET`, makes these tests fail. Both mutations were checked.

- `pnpm test` pulls two pinned images (Alpine, Envoy) the first time.
- **CRLs** (cancelling one certificate before it expires) aren't configured. Short certificate lifetimes, plus the existing per-key revocation for API keys, cover it for now; Envoy supports CRLs when needed.

### 7. Part B: the services trust the header only from Envoy itself (2026-10-07)

**Finding.** On Docker Desktop, Envoy's connections reach the services on the host from `127.0.0.1`, exactly like any other local program. A "trusted proxy address" check therefore can't tell Envoy from a local attacker forging `x-forwarded-client-cert`. The founder chose to make Envoy prove itself instead.

**Decision.**

- **Envoy authenticates to the services with its own certificate.** Each Envoy cluster uses upstream TLS with a client certificate whose SAN is `spiffe://custos.local/proxy/envoy`, and checks the service's server certificate (`host.docker.internal`).
- **Revocation and audit get an optional second listener, TLS only.** It serves the same Fastify app (`createEnvoyOnlyTlsListener`, via Fastify's `serverFactory`). It requires a client certificate from the Custos CA and drops any connection whose certificate isn't Envoy's, including a genuine Custos service going around Envoy. The plain listener is unchanged.
- **The identity header counts only on a connection whose verified TLS peer is Envoy.** `requireScope` reads the peer's SAN from the socket itself (`verifiedPeerUris`), never from the request. There, `x-forwarded-client-cert` is parsed strictly: one element, one URI. It is then mapped to a service `Principal` with that service's scopes (`SERVICE_IDENTITY_SCOPES`, matching `dev-keys`). Everywhere else the header is ignored, and the API-key path applies unchanged. No IP addresses are trusted anywhere.
- **Callers.** Identity, vault and revocation call through Envoy with `createMtlsFetch`, a `fetch` built on `node:https`. Node's global `fetch` can't present a client certificate without the `undici` package, so there's no new dependency. Each caller takes **exactly one** of its service API key or its client certificate (`<SERVICE>_MTLS_CERT`, `<SERVICE>_MTLS_KEY`, `MTLS_CA`). Both the env schema and `resolveOutgoingServiceAuth` enforce this at boot. The certificate is checked to carry that service's SPIFFE ID, be valid now, chain to the CA, and match its key. With mTLS, the target URLs are Envoy's `https://` listeners.
- **Operators** still use API keys; SSO is next.
- **Certificates** are valid from one hour before generation, because a service checks its certificate at boot, often seconds after it was made, and Docker's clock can run ahead of the host's.

**Proof.**

- `mtls-node.test.ts`, with real certificates and TLS: the forwarded identity is accepted from Envoy's certificate. It is refused from the plain port, from a genuine service connecting directly, and with no, expired, wrong-CA or self-signed certificate. A forwarded service lacking the scope is refused.
- `mtls.test.ts`: header parsing and mapping.
- `mtls-proxy.test.ts`: the upstream sees Envoy as the verified peer.
- `packages/sdk/src/mtls.e2e.test.ts` runs the real services behind the real Envoy **with no service keys at all**. Registration, grant, call and revocation work. The audit log names identity's certificate as the reporter of `status.allocate`. A forged header on a plain port gets a 401, and a service bypassing Envoy is dropped. Switching the mTLS path off in the guard makes registration fail, which confirms the test proves mTLS.
- A live run of the built services (`pnpm dev:mtls`) confirmed the same, and that a service given another service's certificate, or both a key and a certificate, refuses to boot.

**Consequences.** `pnpm dev:mtls` generates certificates and config, then starts Envoy (Compose profile `mtls`). The default quickstart is unchanged, on API keys. Local dev ports: Envoy 5003 (revocation) and 5004 (audit); service TLS listeners 4013 and 4014.

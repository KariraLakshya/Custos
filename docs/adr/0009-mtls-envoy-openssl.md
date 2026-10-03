# 0009: mTLS through Envoy, with certificates made by openssl in Docker

**Status:** Accepted, 2026-10-03. Refines ADR 0008 §9. Part A (the proxy, certificates and proxy tests) is implemented; part B (services trusting the proxy's identity header, callers presenting certificates) follows.

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
- **Part B** comes next:
  - Services accept `x-forwarded-client-cert` **only from the proxy's address** (a configured trusted proxy), as a second layer behind `SANITIZE_SET`. Without that rule, a request that bypasses the proxy could forge an identity.
  - The header is mapped to a service `Principal`.
  - Callers present their certificate through Node's built-in `https`, with no new dependency.
  - Envoy is added to the dev setup, and the README is updated.
- **CRLs** (cancelling one certificate before it expires) aren't configured. Short certificate lifetimes, plus the existing per-key revocation for API keys, cover it for now; Envoy supports CRLs when needed.

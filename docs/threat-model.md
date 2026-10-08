# Custos — Threat model

**As of:** Phase 5b (auth hardening) complete, 2026-10-08. It describes the code on `main`, not the target architecture. Update it when a trust boundary, a key, or an accepted risk changes.

**Readers:** engineers changing a security path, and security reviewers. For each threat it gives the control, the test that proves the control in CI, and the risk that remains. The reasons behind each decision are in `docs/adr/`; this file only cites them.

---

## 1. What is being protected

| Asset                                       | Where it lives                                                                                              | Why it matters                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Tool credentials** (e.g. a Stripe key)    | `services/vault`, `tool_credentials`, encrypted with XChaCha20-Poly1305 under `VAULT_MASTER_KEY` (ADR 0004) | Directly usable against the real tool. The thing agents must never hold.           |
| **Issuer signing key**                      | AWS KMS (`IDENTITY_KEY_PROVIDER=kms`), or a dev key from `IDENTITY_ISSUER_SEED` (ADR 0007)                  | Whoever signs with it can mint any agent.                                          |
| **Agent private keys**                      | With the agent only: `agent.key` (0600) from the CLI, `Agent.secretKey` from the SDK                        | Proves the agent is the one its credential names. Custos never sees it.            |
| **Operator and service API keys**           | Holder only; `api_keys` stores a SHA-256 hash (ADR 0008). SSO keys: `~/.custos/operator.key`, 0600          | Register agents, grant tools, revoke, store tool credentials, write audit records. |
| **mTLS private keys** (services, Envoy, CA) | `infra/mtls/` output, 0600, dev CA generated locally (ADR 0009)                                             | Service identity on the mTLS path.                                                 |
| **Revocation state**                        | `services/revocation` (status list, tombstones); vault's in-memory cache                                    | A revoked agent must stop working everywhere, quickly.                             |
| **Policy (allowlists)**                     | `services/vault`, `agent_policies` (deny by default)                                                        | Which agent may use which tool.                                                    |
| **Audit trail**                             | `services/audit`, `audit_records`                                                                           | The evidence of who did what, under whose authority (CLAUDE.md §10).               |

## 2. Trust boundaries

```
 agent process ──(1)──► vault /tokens, /call ──► connector ──(5)──► real tool API
 operator / CLI / SDK ──(2)──► identity, vault, revocation (control-plane writes)
 identity, vault, revocation ──(3)──► revocation, audit (service calls; API key or mTLS via Envoy)
 revocation ──(4)──► vault POST /revocations (signed tombstone push)
 anyone ──(6)──► GET endpoints: DID documents, status list, /revocations, audit /records
 all services ──(7)──► one shared Postgres
```

1. **Agent → vault.** The agent presents an issuer-signed credential plus a proof of possession; it receives a 60 s token scoped to one tool.
2. **Operator → control plane.** Every write needs an operator key with the right scope, from `custos-admin` or an SSO login.
3. **Service → service.** A service key with that service's scopes, or a client certificate through Envoy.
4. **Revocation push.** Keyless by design: it's authenticated by the tombstone's signature.
5. **Vault → tool.** The vault decrypts the tool credential and calls the tool; the agent never sees it.
6. **Public reads.** Signed, already-public artifacts. The open audit read is a decision, not an oversight (ADR 0008, decision 3).
7. **Database.** Not a boundary Custos defends: see §5.

## 3. Attackers considered

- **A1 — Credential thief.** Has an agent's `agent.json` (copied file, leaked log, compromised repo), but not its private key.
- **A2 — Compromised or misbehaving agent.** Holds its own credential and private key and tries to exceed its grants or outlive its revocation.
- **A3 — Network attacker.** Can observe or replay requests, or connect to any service port.
- **A4 — Unauthorised operator.** No key, a wrong-scoped key, an expired key, or an SSO account outside the allowed groups.
- **A5 — Rogue local process.** Runs on the same host as the services and can reach their plain ports, including forging proxy headers.
- **A6 — Forger.** Tries to plant false audit records or false revocation state.

## 4. Threats, controls, and proof

Each row's proof runs in CI (`pnpm test` or `pnpm test:e2e`).

### Identity and credentials

| Threat                                                  | Control                                                                                                   | Proof                                                                                                                                                                             |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1 uses a copied credential                             | `/tokens` requires a proof signed by the key embedded in the credential (ADR 0007)                        | `services/vault/src/server.test.ts` "401s a copied credential presented without the agent's private key"; `packages/sdk/src/sdk.e2e.test.ts` "gives a copied credential nothing…" |
| A3 replays a captured token request                     | Proof carries `aud`, `iat` (±60 s), and a unique `jti` held in a replay cache that fails closed when full | `services/vault/src/server.test.ts` "401s the same proof sent twice"                                                                                                              |
| Tampered credential                                     | JSON-LD Data Integrity verification against the pinned issuer (`VAULT_TRUSTED_ISSUER_DID`) (ADR 0001)     | `sdk.e2e.test.ts` "rejects a tampered credential at token issuance"                                                                                                               |
| Credential from another issuer                          | Vault trusts exactly one issuer DID                                                                       | `services/vault/src/tokens/issue.test.ts` (`UNTRUSTED_ISSUER`)                                                                                                                    |
| Identity restart invalidates credentials (availability) | Stable issuer key: KMS or a seeded dev key                                                                | `services/identity/src/server.test.ts` "keeps issued credentials valid across a restart with the same issuer key"                                                                 |
| A4 registers an agent                                   | `POST /agents` needs an operator key with `agents:register`                                               | `services/identity/src/server.test.ts`; `sdk.e2e.test.ts` "can't register, grant or deprovision with a wrong or unscoped key…"                                                    |
| Oversized or malformed registration input               | Bounded Zod schemas; oversized proof refused before parsing                                               | `services/identity/src/server.test.ts` "an oversized proof, before parsing it"                                                                                                    |

### Authorization and tool access

| Threat                             | Control                                                                                          | Proof                                                                                                                      |
| ---------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| A2 calls a tool it wasn't granted  | Deny-by-default `agent_policies`, checked at token issuance; token bound to one tool (ADR 0006)  | `sdk.e2e.test.ts` (deny before grant, per-tool allowlist)                                                                  |
| A2 obtains the raw tool credential | The credential is decrypted only inside the vault for the outbound call; no response contains it | `services/vault/src/server.test.ts` "runs the full Phase 2 lifecycle…" (token and call responses never contain the secret) |
| Expired token reused               | 60 s TTL, checked on every `/call`, not configurable off                                         | `services/vault/src/server.test.ts` "runs the full Phase 2 lifecycle: … watch the token expire…"                           |

### Revocation

| Threat                                    | Control                                                                                                                                           | Proof                                                                                                                                                         |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A2 keeps working after revocation         | Signed tombstone pushed to the vault; revocation keyed on `credentialSubject.id`; connectors also honour it (ADR 0005)                            | `services/vault/src/tokens/issue.test.ts` "denies a revoked agent — and only that agent, though both share one issuer"; e2e: three tools cut off in under 1 s |
| Vault misses pushes (outage)              | Periodic resync; past `REVOCATION_MAX_STALENESS_MS` (30 s default) the vault denies every call. A resync with any unverifiable entry is not fresh | `services/vault/src/revocation/cache.test.ts` "goes stale again once the configured bound elapses"                                                            |
| A6 forges a tombstone                     | Tombstone signature verified against the revocation service's DID                                                                                 | `services/vault/src/server.test.ts` "401s a tombstone that fails to verify"                                                                                   |
| A4 revokes, or exhausts status-list slots | `agents:revoke` (operator) and `status:allocate` (service only) scopes                                                                            | `services/revocation/src/server.test.ts`                                                                                                                      |

### Control-plane authentication

| Threat                                              | Control                                                                                                   | Proof                                                                                                                                          |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| A4 with no, wrong-scoped, or expired key            | `requireScope` on every write; one uniform `401 UNAUTHORIZED`, so the reason isn't disclosed              | `packages/control-plane-auth/src/fastify.test.ts` "refuses unauthenticated, wrongly-scoped and expired keys with one uniform error"            |
| Key guessing                                        | 10 failures in 5 min lock the source for 15 min; hashes compared in constant time                         | `fastify.test.ts` "locks out a source after repeated failures…"; `lockout.test.ts`                                                             |
| Key stolen from the database                        | Only a SHA-256 hash is stored                                                                             | `store.test.ts` "creates a key that then authenticates, storing only its hash"                                                                 |
| Operator key used as a service key                  | Service-only scopes refused on operator keys at creation and at authentication                            | `authenticator.test.ts` "drops service-only and unknown scopes from an operator key's row"                                                     |
| A3/A5 with a bad client certificate                 | Envoy requires a client cert from the Custos CA, with a per-listener SAN allowlist (ADR 0009)             | `mtls-proxy.test.ts` (expired, wrong CA, self-signed, wrong SAN: each refused with its TLS alert)                                              |
| A5 forges `x-forwarded-client-cert` on a plain port | The header counts only when the socket's verified TLS peer is Envoy; Envoy overwrites it (`SANITIZE_SET`) | `mtls-node.test.ts`; `mtls.e2e.test.ts` "ignores a forged identity header sent straight to a service's plain port"                             |
| A genuine service bypasses Envoy                    | Envoy-only TLS listener drops any peer that isn't Envoy                                                   | `mtls.e2e.test.ts` "drops a genuine service that bypasses Envoy…"                                                                              |
| Forged or replayed SSO login                        | OIDC with PKCE, single-use `state`, nonce, signature checks always on (ADR 0010); unmapped group refused  | `services/identity/src/sso/sso.test.ts`: bad signature, wrong issuer, audience or nonce, expired token, replayed state; `sso-keycloak.test.ts` |

### Audit

| Threat                          | Control                                                                    | Proof                                                                                                   |
| ------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| A6 posts a forged record        | `POST /records` needs `audit:write` (service key or certificate)           | `services/audit/src/server.test.ts` "refuses a forged record with no key, and never stores or signs it" |
| An admin action goes unrecorded | Every control-plane write is audited with its principal, allowed or denied | `services/vault/src/server.test.ts` "audits a stored credential and a grant with the operator…"         |
| Secrets leak into logs          | Pino redaction in `packages/observability` (including `authorization`)     | `packages/observability` "redacts an authorization header…"                                             |

## 5. Accepted risks and known gaps

What the controls above **don't** cover, stated so nobody assumes otherwise. This section is the home for accepted risks; `docs/state.md` "Known issues" tracks the debt among them that is due to be fixed.

**Roots of trust**

- **The database is trusted.** Anyone who can write to Postgres can create API keys (`custos-admin` works by direct DB access), grant tools, or **edit audit rows**. Audit records are signed when read, not when written, and aren't hash-chained (ADR 0006): a signature proves the audit service served the row, not that the row is unchanged since it was written.
- **`VAULT_MASTER_KEY`** is one symmetric key for every stored tool credential, held in the vault's environment. No per-tool keys, no rotation (ADR 0004).
- **Only the issuer key can use KMS.** The vault's token key and the revocation and audit signing keys are in memory and change on restart. That's safe, because tokens live 60 s and audit rows are signed at read time, but those keys aren't in a KMS. `IDENTITY_ISSUER_SEED` (the dev issuer key) is a secret in the environment.
- **The dev CA** is generated locally and has no revocation list (CRLs). Short certificate lifetimes bound this (ADR 0009).

**Within the 60 seconds**

- A **scoped token is a bearer token** for its lifetime: proof of possession is checked at `/tokens`, not on `/call`. A stolen token works for up to 60 s, for its one tool.
- **Revocation can lag** by up to `REVOCATION_MAX_STALENESS_MS` (30 s) if pushes stop arriving. After that the vault denies everything.
- An **SSO key lasts up to 8 h** (max 24 h). Disabling the user at the identity provider doesn't end it; `custos-admin key revoke` does. No back-channel logout.

**Single-instance assumptions**

- The **replay cache** and the **auth lockout** are in memory, so they're correct for one instance of each service only.

**Information disclosure**

- `GET /records` (audit) and `GET /revocations` are open, so anyone who can reach them sees agent DIDs, tools, decisions, and the operators' names, which for SSO operators are their **email addresses**. This lasts until the dashboard gets SSO and an `audit:read` scope (ADR 0008, decision 3).

**Denial of service**

- There's no general rate limiting. The body limit is Fastify's default (1 MiB). Bounded stores (replay cache, login store) refuse new work when full, which fails closed.

**Audit completeness**

- Authentication failures and proof-of-possession failures are **logged, not audited**: they have no principal, and auditing them would let anyone flood the evidence log.
- The audit service doesn't record **which service reported** each event. A service holding `audit:write` vouches for its own reports.

**Outside Custos's control**

- **Agent key custody.** If the agent's host is compromised, the attacker has the agent's private key and _is_ the agent until it is revoked. Custos limits what that agent can reach (its grants, 60 s tokens) and how long (revocation). It doesn't prevent the compromise.
- **What an agent does within its grants.** Custos decides whether an agent may call a tool, not whether a particular call is wise (prompt injection, misuse within scope). Data categories are a static declaration per tool, not inspection of the data (CLAUDE.md §2).
- **Network egress.** Nothing stops an agent calling a tool directly with credentials it got elsewhere. Custos only ensures it never gets them _from Custos_. Egress enforcement is later work (CLAUDE.md §2).
- **Supply chain.** The lockfile, `pnpm audit`, Gitleaks, Semgrep and Dependabot run in CI. One advisory (`braces`, GHSA-vfj7-8cjw-p6xm, dev tooling only, no fix published) is ignored on purpose; see `docs/state.md`.

## 6. Phase 5b DONE criteria → proof

| Criterion (`docs/build-plan.md`)                                             | Test                                                                                                   |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| A copied credential without its private key is refused at `/tokens`          | `services/vault/src/server.test.ts`, `packages/sdk/src/sdk.e2e.test.ts`                                |
| A replayed proof is refused                                                  | `services/vault/src/server.test.ts` "401s the same proof sent twice"                                   |
| An identity restart doesn't invalidate issued credentials                    | `services/identity/src/server.test.ts` "keeps issued credentials valid across a restart…"              |
| A revoked agent is denied, keyed on the subject                              | `services/vault/src/tokens/issue.test.ts` "denies a revoked agent — and only that agent…"              |
| Unauthenticated, wrongly-scoped, expired operator keys get one uniform error | `packages/control-plane-auth/src/fastify.test.ts`, plus each service's `server.test.ts`                |
| No registration without `agents:register`                                    | `services/identity/src/server.test.ts`, `sdk.e2e.test.ts`                                              |
| No audit insert without a service key                                        | `services/audit/src/server.test.ts` "refuses a forged record with no key…"                             |
| mTLS rejects expired, wrong-CA, self-signed, mismatched-SAN certificates     | `packages/control-plane-auth/src/mtls-proxy.test.ts`, `mtls-node.test.ts`                              |
| SSO rejects a bad signature, issuer, audience, nonce, and expired tokens     | `services/identity/src/sso/sso.test.ts` "refuses an ID token with …"                                   |
| The full `pnpm test:e2e` lifecycle passes on the new flow                    | `packages/sdk/src/sdk.e2e.test.ts`, `packages/sdk/src/mtls.e2e.test.ts` (CI `ci.yml`, `pnpm test:e2e`) |

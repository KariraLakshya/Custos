# 0022: Usability — reading grants, agent names, refusal reasons, and the dashboard's audit check

**Status:** Proposed 2026-11-13. The founder decided on 2026-11-13 that names are given at registration, that they are shown but never used to choose an agent, and that forged or broken passes are shown grey but counted.

## Context

In Phase 8b (`docs/build-plan.md`) the dashboard and the CLI must answer three questions without the README: is anything wrong right now, who can do what, and what happened (and can I prove it). Four gaps stop that today:

1. **Nothing can read grants back.** The vault only writes them (`POST /policies`, `services/vault/src/server.ts`). The grant is stored first and then reported to audit without waiting (`auditReporter.report`), so a grant can exist with no audit entry. Grants made before ADR 0008 §7 have no entry either. A "who can do what" list rebuilt from the audit log could therefore show an agent as unable to use a tool that it can use. For a security product that is the dangerous direction.
2. **Agents have no names.** The identity `agents` table holds an id, a DID and a key. `POST /agents` takes only `{publicKey, proof}`. People already have names: `AuditPrincipal.name` is the operator's SSO email.
3. **Refusal codes are scattered.** About 25 vault codes are string literals across `services/vault/src`, delegation reasons such as `NOT_COVERED` and `CHAIN_ENDS_NOW` are separate, and `packages/contracts` `ErrorCode` has 6. Nothing says in plain words what a code means or which command fixes it. Nothing says whether it is the product working normally or a real problem.
4. **The dashboard does not check the audit log.** It decodes records without verifying them and labels itself "not a verification tool" (`apps/dashboard/src/server.ts`). To answer "can I prove it" it needs a verified or tampered result.

## Decision

### 1. Grants are read from the vault, the only reliable source

- New vault route `GET /policies` returns grants: agent DID, tool, granted by (kind, id, name, via) and `created_at`. With `?agent=<did>` it returns that agent's grants. Without it, it returns every grant as a bounded, paged list (a page limit and a cursor), so the dashboard does not need one request per agent. It never returns tool credentials. A malformed DID, a page limit over the maximum or an unknown parameter gets `400 INVALID_INPUT`.
- New operator scope `policies:read` (`packages/control-plane-auth` `OPERATOR_SCOPES`). The route is closed like every control-plane write: there is no open read. `GET /records` on audit stays open, as ADR 0008 decision 3 left it, and that is unchanged here.
- **Keys made at sign-in** (`custos login`, ADR 0010) get their scopes from `SSO_GROUP_SCOPES`, which maps company groups to scopes. A group gets the new read scopes only by being listed there. The dev and demo SSO configuration (`infra/` Keycloak realm, `.env.example`, `apps/admin/src/demo.ts`) adds both read scopes to the operator group, so `custos status` works for a signed-in operator.
- Reads are not audited. An audit entry per dashboard poll would flood the ledger, and a read changes nothing.

### 2. Agents get a name at registration, shown only

- `custos register --name <name>`. Identity `POST /agents` accepts an optional `name`. Migration `0014` adds a nullable `agents.name`, and it is reversible.
- Validation: 1 to 64 characters, `^[A-Za-z0-9][A-Za-z0-9 ._-]*$`. Anything else gets `400 INVALID_INPUT`. **Names are not unique and never pick an agent.** Every command keeps taking the agent's id or DID and prints the name beside it, so two agents called `billing-bot` cannot cause the wrong one to be revoked. An agent with no name is shown as "unnamed" plus a short form of its DID.
- New identity route `GET /agents` (optionally `?id=` or `?did=`) returns id, DID, name, registration time and registering principal. It needs the new operator scope `agents:read`.
- The name is **not** written into audit records. That would change the hashed ledger format (ADR 0017). The dashboard and CLI look names up from identity when they display them.

### 3. One catalogue of refusal reasons in `packages/contracts`

- `refusals.ts` maps every code the vault, revocation, identity and SDK can return, and every delegation reason, to `{ meaning, nextStep, severity }`. `meaning` is plain words, `nextStep` is the command that fixes it (or "none: this is the product working"), and `severity` is `normal` or `alarm`.
- Services import their codes from the catalogue instead of writing string literals. A test fails if any code a service can emit has no entry.
- **Severity.** `normal` (grey, counted) covers the product working as intended: not granted, revoked, wrong tool or action, a delegation that does not cover the request, and a forged or broken pass (bad proof, replay, invalid token), as decided by the founder. `alarm` (red) is kept for real problems. `REVOCATION_STATE_UNKNOWN_AGENT` is `normal`: it is routine. An agent that has not asked for a token recently and has had no push is refused once, asks again and carries on (`docs/state.md`). Every code's severity is set explicitly in the catalogue, with no default, so a new code cannot turn the dashboard red by accident. The real problems are: stale revocation state, an unverifiable status list or issuer, a service that is down, a tampered audit log, and a seal copy that failed. A rule that turns a spike of grey refusals red is left for later.
- The CLI prints `meaning` and `nextStep` for every refusal. Errors it throws itself (missing files, missing operator key, bad flags) follow the same shape.

### 4. The dashboard gets a small read-only back end that verifies the audit log

- `apps/dashboard`'s Node process gains GET-only `/api/*` routes. The browser talks only to them, never to the services directly. Every other method gets `405`. Every upstream call has a timeout and a response size cap.
- They combine: service health; vault and revocation freshness; seal status; grants (`policies:read`); names (`agents:read`); the audit log, verified.
- **The dashboard and `custos audit-log` give the same verdict on the same log.** The check has two parts, and both are shared:
  - **Seals and payloads.** `pullAuditLedger` is also exported from a new subpath, `@custos/audit-client/ledger`, which imports only `@custos/core`. The package root still exports it, so the CLI is unchanged.
  - **Delegation chains.** The re-check now in `apps/cli/src/delegation-audit.ts` (`DELEGATION_INVALID`, `UNLINKED`, `UNCHECKABLE`) also imports only `@custos/core`. It moves into the same subpath, and the CLI imports it from there.

  The dashboard therefore does not take in `pg` or the AWS SDK, and neither the security-critical fetch order nor the chain check is copied. Verification runs on a slow cadence (about 15 s), because it reads the whole ledger.

- **Trust.** The dashboard pins the first seal key it sees and keeps the newest verified seal in memory, so a key swap (`UNTRUSTED_KEY`), a rewrite (`DIVERGED`) and a truncation (`TRUNCATED`) are caught while it runs. That trust starts fresh on every restart, and the page says so, together with "for an independent check, run `custos audit-log`". The CLI remains the independent check, because it keeps state on disk and can read the outside seal store.
- **Its key.** The dashboard holds a service key with `policies:read` and `agents:read`, and no other scope. It comes from the environment (`DASHBOARD_API_KEY`), is validated at startup in `packages/config`, is redacted by the logger, and never reaches the browser.
- **Exposure.** There is no dashboard login in this phase (`docs/build-plan.md`). Anyone who can reach port 4005 can therefore read grants and names. Two defaults limit this. The dashboard listens on `127.0.0.1` (a new `DASHBOARD_HOST`). The container image sets `0.0.0.0` inside its own network namespace, and compose publishes the port only on the host's `127.0.0.1`. Two more rules stop another website from reading it through the visitor's browser (DNS rebinding). `/api/*` refuses any request whose `Host` header is not `localhost:<port>` or `127.0.0.1:<port>`. And `/api/*` sends no `access-control-allow-origin` header, unlike audit's and revocation's open reads, which send `*`. Both rules get negative tests. `docs/threat-model.md` records the exposure until dashboard SSO exists.
- **The three views.** _Now_, _Who can do what_ and _Proof_ are built as pure view-model modules, in the style of `foreign.ts`, that render escaped strings through one `escapeHtml`. They are tested against a real sealed audit log recorded as fixtures (clean, tampered, truncated, delegated) and generated once with a seeded key and a fixed clock. Delegation chains are shown "as used": hand-offs that were never presented are not stored anywhere.

### 5. CLI names in the user's words

- `revoke` replaces `deprovision`, which remains an alias. Old names keep working, and the existing e2e tests keep using `deprovision` to prove it.
- `custos` with no arguments lists the lifecycle in order: login, register, grant, use, delegate, revoke, audit-log, status.
- `custos status <agent id or DID>` shows the agent's name, its grants (vault), whether it is revoked (revocation) and its recent actions (audit). It needs an operator key.

## Consequences

- There are two new operator scopes, `policies:read` and `agents:read`, and one new service key for the dashboard. Existing keys do not gain them. `custos-admin dev-keys`, `apps/admin/src/demo.ts` and `images/up.sh` create the dashboard key.
- Identity gains a nullable column (migration `0014`). Agents registered earlier show as unnamed.
- Services change from string literals to catalogue constants. The codes sent on the wire do not change.
- The dashboard is no longer "not a verification tool". Its result is still weaker than `custos audit-log`'s, and it says so.
- `docs/threat-model.md` gains the dashboard exposure. README and `docs/readme-test.md` switch to `revoke`.

## Alternatives rejected

- **Rebuilding grants from the audit log.** No new endpoint, but grants can be missing from the log (Context 1), so the "who can do what" view could under-report what an agent can do.
- **Names held only in the dashboard's browser.** The CLI and other machines would never see them.
- **Names usable in commands.** They would need to be unique, and a typo or a reused name would target a real agent.
- **Copying the audit fetch into the dashboard.** Two copies of the seal-before-entries order would drift apart.

## Open questions

- If a deployment enforces mTLS between services (`MTLS_*`), the dashboard's back end needs a client certificate. Check this when building step 7.

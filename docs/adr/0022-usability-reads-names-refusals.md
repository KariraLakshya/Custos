# 0022: Usability — dashboard sign-in, closed reads, agent names, refusal reasons

**Status:** Proposed 2026-11-13. The founder decided on 2026-11-13:

- names are given at registration, and shown but never used to choose an agent;
- forged or broken passes are shown grey but counted;
- the dashboard is secured with the existing company sign-in (ADR 0010), and the open audit and revocation reads are closed in the same phase. This widens Phase 8b's "no login beyond what exists" (`docs/build-plan.md`, updated to match).

## Context

In Phase 8b (`docs/build-plan.md`) the dashboard and the CLI must answer three questions without the README: is anything wrong right now, who can do what, and what happened (and can I prove it). Five gaps stop that today:

1. **Nothing can read grants back.** The vault only writes them (`POST /policies`, `services/vault/src/server.ts`). The grant is stored first and then reported to audit without waiting (`auditReporter.report`), so a grant can exist with no audit entry. Grants made before ADR 0008 §7 have no entry either. A "who can do what" list rebuilt from the audit log could therefore show an agent as unable to use a tool that it can use. For a security product that is the dangerous direction.
2. **Agents have no names.** The identity `agents` table holds an id, a DID and a key. `POST /agents` takes only `{publicKey, proof}`. People already have names: `AuditPrincipal.name` is the operator's SSO email.
3. **Refusal codes are scattered.** About 25 vault codes are string literals across `services/vault/src`, delegation reasons such as `NOT_COVERED` and `CHAIN_ENDS_NOW` are separate, and `packages/contracts` `ErrorCode` has 6. Nothing says in plain words what a code means or which command fixes it. Nothing says whether it is the product working normally or a real problem.
4. **The dashboard does not check the audit log.** It decodes records without verifying them and labels itself "not a verification tool" (`apps/dashboard/src/server.ts`). To answer "can I prove it" it needs a verified or tampered result.
5. **The dashboard and the data behind it are open.** The dashboard has no sign-in. Audit `GET /records` and revocation `GET /revocations` are readable by anyone who can reach them, and send `access-control-allow-origin: *`. That exposes agent DIDs, tools, decisions and operators' email addresses (`docs/threat-model.md`). ADR 0008 decision 3 left this open "until the dashboard gets operator login (SSO)". That is this phase. Locking the dashboard alone would leave the services behind it readable directly.

## Decision

### 1. Grants are read from the vault, the only reliable source

- New vault route `GET /policies` returns grants: agent DID, tool, granted by (kind, id, name, via) and `created_at`. With `?agent=<did>` it returns that agent's grants. Without it, it returns every grant as a bounded, paged list (a page limit and a cursor), so the dashboard does not need one request per agent. It never returns tool credentials. A malformed DID, a page limit over the maximum or an unknown parameter gets `400 INVALID_INPUT`.
- It needs the new scope `policies:read`.

### 2. Agents get a name at registration, shown only

- `custos register --name <name>`. Identity `POST /agents` accepts an optional `name`. Migration `0014` adds a nullable `agents.name`, and it is reversible.
- Validation: 1 to 64 characters, `^[A-Za-z0-9][A-Za-z0-9 ._-]*$`. Anything else gets `400 INVALID_INPUT`. **Names are not unique and never pick an agent.** Every command keeps taking the agent's id or DID and prints the name beside it, so two agents called `billing-bot` cannot cause the wrong one to be revoked. An agent with no name is shown as "unnamed" plus a short form of its DID.
- New identity route `GET /agents` (optionally `?id=` or `?did=`) returns id, DID, name, registration time and registering principal. It needs the new scope `agents:read`.
- The name is **not** written into audit records. That would change the hashed ledger format (ADR 0017). The dashboard and CLI look names up from identity when they display them.

### 3. Every read of agent data needs a key; the open reads close

There are four read scopes, all operator scopes (`packages/control-plane-auth` `OPERATOR_SCOPES`):

| Scope              | Routes it opens                                                         |
| ------------------ | ----------------------------------------------------------------------- |
| `audit:read`       | audit `GET /records`, `GET /seals/status`                               |
| `revocations:read` | revocation `GET /revocations`; vault `GET /revocations` (its freshness) |
| `policies:read`    | vault `GET /policies`                                                   |
| `agents:read`      | identity `GET /agents`                                                  |

- These routes lose `access-control-allow-origin: *`. Without a valid key with the scope they answer `401 UNAUTHORIZED`. That is what the existing guard (`packages/control-plane-auth` `fastify.ts`) answers for every authentication or scope failure, per ADR 0008 §3. Negative tests cover each route: no key, a wrong key, an expired key, and a key without the scope.
- **Still open, on purpose.** DID documents (`/.well-known/did.json`, `/agents/:id/did.json`) and the signed status list (`GET /status/revocation`) stay open. Verifiers must read them to check a credential offline, without the issuer's help (CLAUDE.md §3), and the status list holds only bits. `/health` holds no data and stays open.
- **Callers that change.** `custos audit-log` sends the operator key (from `custos login` or `CUSTOS_OPERATOR_KEY`). `@custos/audit-client`'s ledger fetch takes a key. Before the routes close, every caller is found and given a key: services, the federation publisher, tests, and also shell scripts, `.mjs`, CI YAML, compose files and `index.html`. That includes `infra/docker/checks/*` and `images/up.sh`, which feed the `images` CI job. A missed caller fails closed, as a refused read.
- **Order, so `pnpm demo` keeps working at every step.** The scopes, the `SSO_GROUP_SCOPES` and dev-key configuration that lists them, and the callers sending a key all land first; a key sent to a still-open route does no harm. The scopes and the configuration go in one PR, because `SSO_GROUP_SCOPES` refuses unknown scopes at boot. The routes close in the same PR that moves the dashboard page onto its own `/api/*`. Until then, the current page keeps reading them directly.
- **Existing local keys.** `custos-admin dev-keys` and `images/up.sh` recreate a key when it lacks a scope it now needs, not only when it is no longer active. Otherwise keys already on a machine would break `custos audit-log` there.
- **Who gets the scopes.** Keys made at sign-in (`custos login`, ADR 0010) get their scopes from `SSO_GROUP_SCOPES`, which maps company groups to scopes. A group gets a read scope only by being listed there, so a company can give an auditor `audit:read` and nothing else. The dev and demo configuration (the `infra/` Keycloak realm, `.env.example`, `apps/admin/src/demo.ts`, `custos-admin dev-keys`, `images/up.sh`) gives the operator group all four.
- Reads are not audited. An audit entry for every dashboard refresh would bury the real events, and a read changes nothing. Sign-ins are audited, as they already are (ADR 0010).

### 4. The dashboard signs people in with the company sign-in

- **No shared key.** The dashboard holds no key of its own and needs no `DASHBOARD_API_KEY`. It reads with a key made for the signed-in person, so it shows only what that person's group may see.
- **The dashboard can only ever read.** When a sign-in is started with `returnTo`, identity issues a key with only those of the group's scopes that are among the four read scopes. A person whose group may revoke agents or grant tools still gets a read-only key at the dashboard. Identity enforces this, and the caller cannot widen it. A compromised dashboard process can therefore read but never change anything. A test proves that an admin's dashboard key is refused by `POST /policies` and `POST /revocations`. A view whose scope the person lacks says so in words ("your group cannot see grants") rather than failing.
- **Signing in** reuses ADR 0010's flow, run by the dashboard's server rather than by the CLI:
  1. `GET /login` on the dashboard calls identity `POST /operator/login` with a `returnTo` address.
  2. The browser is sent to the company login.
  3. Identity's callback redirects back to `returnTo` with a one-time code added, instead of showing "return to your terminal". The code is random, single-use, expires within a minute, and is neither the loginId nor the key.
  4. The dashboard's `/login/done` collects the key only when the request carries both the pending cookie from step 1 and that code. It sends the code to identity, and identity releases the key for a `returnTo` login only with the matching code. The dashboard never polls on its own.
- **Why the code.** An attacker could start a sign-in on their own dashboard and send the company-login link to a victim who is already signed in to the company login. Without the code, the victim's one click would hand the victim's key to the attacker's session. With it, the key is released only to the browser that comes back from the company login, which is the victim's. That browser does not hold the attacker's pending cookie, so nothing is released. A test proves it.
- **`returnTo` is checked exactly.** It must equal one of the addresses in a new identity setting, `SSO_RETURN_URLS`, character for character: no prefix match, no wildcard. Anything else is refused before any redirect, which stops identity being used as an open redirect. Negative tests cover a foreign host, a lookalike prefix, an extra path and an encoded variant. Without `returnTo` the CLI flow is unchanged.
- **Cookies.**
  - **Pending cookie.** It ties a sign-in to the browser that started it. It is short-lived, `HttpOnly` and `SameSite=Lax`. Lax, because the return from a hosted company login (Okta, Entra) is a redirect chain that starts on another site, and a Strict cookie would not be sent. Local Keycloak is on the same site, so a Strict cookie would pass tests and hide that failure.
  - **Session cookie.** It holds a random 32-byte session id and is `HttpOnly`, `SameSite=Strict`, `Path=/` and `Secure` over HTTPS. `/login/done` sets it on a page that then navigates to `/`, so the first load after sign-in already sends it.
  - **The key itself** stays in the dashboard server's memory, mapped to the session id. It never reaches the browser and is never logged (logger redaction).
  - **Pending sign-ins** are bounded in number and time. Identity's sign-in slots are limited and shared with CLI users, so a flood of `GET /login` answers "busy" rather than growing memory.
- **Session end.** A session ends when its key expires (the SSO session length, ADR 0010) or when the person signs out. Signing out is a `POST /logout` that also checks the `Origin` header. A restart of the dashboard ends every session. Sessions live in one process's memory, which is correct for a single dashboard instance only, like the vault's replay cache.
- **Signed out means nothing.** Without a session every `/api/*` returns `401` and the page shows only the sign-in button. The HTML carries no data. A test checks every `/api/*` route signed out.
- **Same-machine and browser protections, kept.**
  - The dashboard listens on `127.0.0.1` by default (a new `DASHBOARD_HOST`). The container image sets `0.0.0.0` inside its own network namespace, and compose publishes the port only on the host's `127.0.0.1`.
  - Every dashboard route, not only `/api/*`, refuses any `Host` header that is not the dashboard's own address (DNS rebinding), and none sends `access-control-allow-origin`.
  - Each has a negative test.

### 5. The dashboard verifies the audit log, with the same verdict as `custos audit-log`

- The dashboard's Node process gains GET-only `/api/*` routes. The browser talks only to them, never to the services directly. Every other method gets `405`, except `POST /logout`. Every upstream call has a timeout and a response size cap.
- They combine: service health; vault and revocation freshness; seal status; grants; names; the audit log, verified.
- **One check, shared.** The check has two parts, both shared:
  - **Seals and payloads.** `pullAuditLedger` is also exported from a new subpath, `@custos/audit-client/ledger`, which imports only `@custos/core`. The package root still exports it.
  - **Delegation chains.** The re-check now in `apps/cli/src/delegation-audit.ts` (`DELEGATION_INVALID`, `UNLINKED`, `UNCHECKABLE`) also imports only `@custos/core`. It moves into the same subpath, and the CLI imports it from there.

  The dashboard therefore does not take in `pg` or the AWS SDK, and neither the fetch order nor the chain check is copied. Verification runs on a slow cadence (about 15 s), because it reads the whole ledger.

- **Trust.** The dashboard pins the first seal key it sees and keeps the newest verified seal in memory, so a key swap (`UNTRUSTED_KEY`), a rewrite (`DIVERGED`) and a truncation (`TRUNCATED`) are caught while it runs. That trust starts fresh on every restart, and the page says so, together with "for an independent check, run `custos audit-log`". The CLI remains the independent check, because it keeps state on disk and can read the outside seal store.
- **The three views.** _Now_, _Who can do what_ and _Proof_ are built as pure view-model modules, in the style of `foreign.ts`, that render escaped strings through one `escapeHtml`. They are tested against a real sealed audit log recorded as fixtures (clean, tampered, truncated, delegated) and generated once with a seeded key and a fixed clock. Delegation chains are shown "as used": hand-offs that were never presented are not stored anywhere.

### 6. One catalogue of refusal reasons in `packages/contracts`

- `refusals.ts` maps every code the vault, revocation, identity and SDK can return, and every delegation reason, to `{ meaning, nextStep, severity }`. `meaning` is plain words, `nextStep` is the command that fixes it (or "none: this is the product working"), and `severity` is `normal` or `alarm`.
- Services import their codes from the catalogue instead of writing string literals. A test fails if any code a service can emit has no entry. Every code's severity is set explicitly, with no default, so a new code cannot turn the dashboard red by accident.
- **`normal` (grey, counted)** is the product working as intended: not granted, revoked, wrong tool or action, a delegation that does not cover the request, and a forged or broken pass (bad proof, replay, invalid token), as decided by the founder. `REVOCATION_STATE_UNKNOWN_AGENT` is `normal` too: an agent that has not asked for a token recently and has had no push is refused once, asks again and carries on (`docs/state.md`).
- **`alarm` (red)** is for real problems: stale revocation state, an unverifiable status list or issuer, a service that is down, a tampered audit log, and a seal copy that failed. A rule that turns a spike of grey refusals red is left for later.
- The CLI prints `meaning` and `nextStep` for every refusal. Errors it throws itself (missing files, missing operator key, not signed in, bad flags) follow the same shape.

### 7. CLI names in the user's words

- `revoke` replaces `deprovision`, which remains an alias. Old names keep working, and the existing e2e tests keep using `deprovision` to prove it.
- `custos` with no arguments lists the lifecycle in order: login, register, grant, use, delegate, revoke, audit-log, status.
- `custos status <agent id or DID>` shows the agent's name, its grants (vault), whether it is revoked (revocation) and its recent actions (audit). It needs an operator key with the read scopes.

## Consequences

- There are four new operator scopes, `audit:read`, `revocations:read`, `policies:read` and `agents:read`, and one new identity setting, `SSO_RETURN_URLS`. Existing keys do not gain the new scopes.
- `custos audit-log` and anything else reading the audit trail or the revocation list now needs a key. This changes behaviour for existing users. README, `docs/readme-test.md` and the demo scripts change in the same PR as the closing.
- **The demo gains a company login.** Today Keycloak (the company-login stand-in) runs only with `pnpm dev:sso`, and `pnpm demo` and the image stack do not start it. Both now do, so the dashboard can be signed in to. The realm already has throwaway users: `alice` in `custos-admins`, `bob` in no group. The README's sign-in step names `alice` for the stranger runs, and `bob` shows the "your group cannot see this" path.
- Identity gains a nullable column (migration `0014`). Agents registered earlier show as unnamed.
- Services change from string literals to catalogue constants. The codes sent on the wire do not change.
- The dashboard is no longer "not a verification tool". Its result is still weaker than `custos audit-log`'s, and it says so.
- `docs/threat-model.md`: the open-reads entry is resolved. New entries cover the dashboard's in-memory sessions and the `returnTo` allow-list.

## Alternatives rejected

- **A dashboard with no sign-in, reachable only from the same computer.** Anyone at that computer would see everything. Rejected by the founder: the dashboard must be secure.
- **A dashboard password.** Anyone with the password sees everything, there is no record of who looked, and the open service reads stay open.
- **A shared dashboard service key.** A stolen dashboard would leak a key that reads everything, and every viewer would see the same thing whatever their group.
- **Locking the dashboard but leaving the service reads open.** The data would still be readable directly from the services.
- **Rebuilding grants from the audit log.** No new endpoint, but grants can be missing from the log (Context 1), so the "who can do what" view could under-report what an agent can do.
- **Names held only in the dashboard's browser.** The CLI and other machines would never see them.
- **Names usable in commands.** They would need to be unique, and a typo or a reused name would target a real agent.
- **Copying the audit fetch into the dashboard.** Two copies of the seal-before-entries order would drift apart.

## Open questions

- **Revoking the key at sign-out.** Signing out ends the dashboard session. The key then lasts until its own expiry, because control-plane keys have no revoke route today. Check this when building sign-in, and add a revoke-on-logout if a route exists or is cheap.
- **mTLS.** If a deployment enforces mTLS between services (`MTLS_*`), the dashboard's server needs a client certificate. Check this when building the dashboard back end.
- **Federation.** Check whether the federation publisher or a partner organisation reads revocation `GET /revocations` rather than the published list. Also check whether the dashboard's "Across organisations" panel, or `pnpm demo:federation`, reads the other organisation's revocation route. Either is a documented demo path. If anything does, it gets a key before the route closes.

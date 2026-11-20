# Not yet production-hardened

Custos is a development build. The controls on the [threat model](/security/) page are real and tested, but the following gaps are known and stated so nobody assumes otherwise. The full list, with the reasoning, is section 5 of [`docs/threat-model.md`](https://github.com/KariraLakshya/Custos/blob/main/docs/threat-model.md).

## Roots of trust

- **The database is trusted.** Anyone who can write to Postgres can create API keys (`custos-admin` works by direct database access), grant tools, or edit audit rows. Edits to sealed audit entries are **detected**, not prevented. Entries newer than the newest outside seal copy can be deleted unnoticed.
- **One master key** (`VAULT_MASTER_KEY`) encrypts every stored tool credential, held in the vault's environment, with no rotation.
- **Not every key can use KMS.** The issuer, revocation and audit keys can. The vault's token key is in memory and changes on restart (safe because tokens live 60 seconds). The development seeds are secrets in the environment.
- **Synchronised clocks are required** between the revocation service and the vault, and on the publisher's machine.
- **The publisher's development seed** must move to KMS before real use. Whoever holds `kms:Sign` on the revocation key can sign any status list.
- **The development certificate authority** has no revocation list.

## Within the 60 seconds

- A **scoped token is a bearer token** for its lifetime and its one tool and action.
- **A captured request can be spent once** on the same tool and action with a different body, within the skew window and before the real agent. The replay cache stops a second use. Accepted.
- **Revocation can lag** by up to `REVOCATION_MAX_STALENESS_MS` (30 seconds) if pushes stop; after that the vault refuses everything.
- An **SSO key lasts up to 8 hours** (at most 24). Disabling the person at the company doesn't end it.

## One instance only

The replay cache, the login lockout, the vault's revocation view and federation's replay guard and status copy are **in memory**, so they are correct for one instance of each service. Running several needs shared stores, which are not built.

## Information disclosure

`GET /records` (audit) and `GET /revocations` are **open**: anyone who can reach them sees agent DIDs, tools, decisions and operators' names, which for SSO operators are email addresses.

## Denial of service

There is no general rate limiting. Bodies are limited to 1 MiB. Bounded in-memory stores refuse new work when full, which fails closed.

## Missing features that affect security

- **No data policy.** Data categories are a fixed declaration per tool. Custos doesn't inspect, filter or mask what a tool returns.
- **No egress enforcement.** Nothing stops an agent calling a tool directly with a credential it got elsewhere; Custos only ensures it never gets one from Custos. A sidecar and eBPF enforcement are planned.
- **No credential expiry.** Agent credentials have no `validUntil`; revocation is the only way to end one.
- **No ungrant**, and no way to cancel one hand-off without revoking an agent.
- **Agent key custody** is the agent deployment's job. A compromised agent host means the attacker is the agent until it is revoked.

## Audit completeness

- Failed authentications and failed proofs are logged, not audited, so nobody can flood the evidence log.
- A service holding `audit:write` can report false events, but each carries that service's identity.
- Revocations made through the cross-organisation publisher are kept in the publisher's own journal, which is not tamper-evident until it is replayed into the audit service.

## Not hosted

There is no hosted Custos yet, no multi-region deployment and no Kubernetes packaging. The [build plan](https://github.com/KariraLakshya/Custos/blob/main/docs/build-plan.md) sets the order.

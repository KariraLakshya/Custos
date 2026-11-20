# Threat model summary

This is a summary of [`docs/threat-model.md`](https://github.com/KariraLakshya/Custos/blob/main/docs/threat-model.md), which lists, for each threat, the control and the test that proves it in CI. It describes the code on `main`, not the target architecture.

## What is protected

| Asset                     | Where it lives                                                           |
| ------------------------- | ------------------------------------------------------------------------ |
| Tool credentials          | The vault, encrypted with XChaCha20-Poly1305 under `VAULT_MASTER_KEY`    |
| Issuer signing key        | AWS KMS, or a development key from `IDENTITY_ISSUER_SEED`                |
| Agent private keys        | With the agent only (`agent.key`, owner-only). Custos never sees them    |
| Operator and service keys | With the holder; the database stores only a SHA-256 hash                 |
| mTLS private keys         | `infra/mtls/certs/`, owner-only, from a locally generated development CA |
| Revocation signing key    | AWS KMS, or `REVOCATION_SIGNING_SEED`. The publisher uses the same key   |
| Revocation state          | The revocation service, and each vault's in-memory view                  |
| Grants                    | The vault, deny by default                                               |
| The audit trail           | The audit service's sealed ledger, with seal copies outside it           |

## Trust boundaries

```text
 agent ──(1)──► vault /tokens, /call ──► connector ──(5)──► real tool API
 operator / CLI / SDK ──(2)──► identity, vault, revocation
 identity, vault, revocation ──(3)──► revocation, audit (service key or mTLS via Envoy)
 revocation ──(4)──► vault POST /revocations (signed tombstone push)
 anyone ──(6)──► open GET routes: DID documents, status list, /revocations, audit /records
 all services ──(7)──► one shared Postgres
```

1. The agent presents an issuer-signed credential and a proof of possession, and gets a 60-second token for one tool.
2. Every control-plane write needs an operator key with the right scope.
3. Services authenticate to each other with a service key or a certificate.
4. The revocation push needs no key: the tombstone's signature is what is trusted.
5. The vault decrypts the tool credential and calls the tool; the agent never sees it.
6. The open reads are signed, already-public artefacts, by decision.
7. The database is trusted: see [Not yet production-hardened](/security/limits).

## Attackers considered

| Who                       | Can                                                                                 | Stopped by                                                                            |
| ------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **Credential thief**      | Holds a copy of `agent.json`, not the key                                           | Proof of possession: a copied credential gets nothing                                 |
| **Misbehaving agent**     | Holds its own credential and key                                                    | Deny-by-default grants, one-tool tokens, revocation, delegation that only narrows     |
| **Network attacker**      | Observes, replays, connects to any port                                             | Proofs bound to audience, time, a one-use id, the tool and action; mTLS through Envoy |
| **Unauthorised operator** | No key, a wrong-scoped or expired key, or an SSO account outside the allowed groups | Scopes on every write, one uniform `401`, lockout after repeated failures             |
| **Rogue local process**   | Reaches the services' plain ports, forges proxy headers                             | Forwarded identity trusted only from the verified Envoy peer                          |
| **Forger**                | Plants false audit entries or revocation state                                      | `audit:write` scope, hash chain and seals, signed tombstones and status lists         |

## What is proven in CI

Each of these is a test that must fail safely, and CI fails if it doesn't: a tampered credential is rejected; a credential signed by an unknown key is rejected; a copied credential without its key is refused; a replayed proof is refused; an expired token is rejected; a revoked agent is denied, and only that agent; a tool outside the grant is refused; no response ever contains the tool secret; unauthenticated, wrongly scoped and expired operator keys get one uniform error; bad client certificates are refused; a forged SSO login is refused; an edited, removed, reordered or rebuilt audit log is detected; malformed and oversized input is refused.

For what these controls do **not** cover, see [Not yet production-hardened](/security/limits).

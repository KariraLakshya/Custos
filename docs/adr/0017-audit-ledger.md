# 0017: The audit log is a hash-chained ledger with signed seals kept outside the database

**Status:** Proposed 2026-10-27 (founder chose this as the next work after ADR 0016, and chose periodic seals plus an outside copy on 2026-10-26). Built in two pull requests against `main`, merged in order: **part 1** (the ledger, stable key, reporter, verifier) and **part 2** (the write-once outside seal store). Accepted when part 2 merges. Supersedes ADR 0006's "no hash-chaining" deferral.

## Context

The audit log is the evidence Custos offers a DPDP auditor (CLAUDE.md §10). Today `services/audit` stores each reported event as plain columns and signs it **only when someone reads it**, with a key generated fresh on every start. So:

- Anyone with database access can insert, edit or delete rows, and the service will sign whatever is there on the next read. The signature proves "the audit service served this", not "this was recorded then".
- The key changes on every restart, so nothing signed yesterday can be checked against today's key.
- The service does not record **which service reported** an event; a service with `audit:write` attests to its own reports.

Two constraints rule out the obvious fixes once the key is in KMS (ADR 0016):

- `GET /records` is open and returns the whole log. Signing on read would cost one KMS call per record per anonymous request: the status-list problem of ADR 0016, multiplied.
- `POST /records` fires on every agent `/call`. Signing each record in KMS at write time takes about 100 ms. That signature has to cover the record's place in the chain, so it would be made while the chain is locked, queueing every append behind KMS. CLAUDE.md §3 treats audit-induced latency as a bug.

## Decision

### 1. A hash chain, built at write time, with no signing on the write path

Each record becomes an **entry**: `seq` (1, 2, 3, ...), the exact payload bytes, `payloadHash = SHA-256(payload)`, and

`hash = SHA-256("custos.audit.entry.v1" ‖ 0x00 ‖ seq as 8 bytes big-endian ‖ prevHash ‖ payloadHash)`

where `prevHash` is the previous entry's `hash`, or 32 zero bytes for entry 1. The payload is the record serialised as JSON **once**, at append, and stored as that exact text; hashes are always taken over the stored text, never rebuilt from columns. The columns stay only for queries. The hashing and verification code is pure, in `packages/core` (`audit/ledger.ts`), using `@noble/hashes`.

An append runs in one transaction that takes a Postgres advisory lock, reads the head, and inserts. Forks are refused by the database itself: `seq` is unique, and so is `prev_hash`, so two appends can never both follow the same entry even if the lock were missing. An append makes no network call.

### 2. Seals: the head, signed periodically

A sealer in the audit service runs every `AUDIT_SEAL_INTERVAL_MS` (default 10 s). If the head has moved since the last seal, it signs

`{ typ: "custos-audit-seal+v1", log: <audit service DID>, seq, headHash, sealedAt }`

as a compact envelope (`base64url(JSON).base64url(signature)`, the same family as tombstones and tokens) and stores it. KMS cost is at most one signature per interval, whatever the traffic. A signing failure skips that tick; appends never wait on it. Seals are unique per `seq`, so two sealers racing produce one seal.

### 3. A stable key

`AUDIT_KEY_PROVIDER=local|kms`, mirroring ADR 0016: `local` needs `AUDIT_SIGNING_SEED` (64 hex, required, no default), `kms` needs `AUDIT_SIGNING_KMS_KEY_ID`. The public key is read at boot and published in the service's did:web document.

### 4. The reporter is recorded

`POST /records` records who sent the event, from the authenticated caller (`principalOf`, which covers both API keys and Envoy-forwarded mTLS identities), as `reportedBy: { kind, id, name }` inside the payload, so it is covered by the chain.

### 5. Reading and verifying

`GET /records` returns the entries and the newest seal; nothing is signed. With `?agentId=`, entries of other agents are returned as `{ seq, payloadHash }` only, so the chain over one agent's entries can still be checked without the other entries' contents. This is a verification property, not privacy: the unfiltered route is still open (ADR 0008 decision 3).

`verifyAuditLedger` (core) recomputes the chain, checks each seal's signature against the audit DID key, and then checks that **the served log matches each seal**: the entry at `seal.seq` must exist (else `TRUNCATED`) and its hash must equal `seal.headHash` (else `DIVERGED`). It takes optional seals the verifier already trusts: the one it remembered from its last run (`custos audit-log` keeps it in `~/.custos/audit-seal.json`) and, from part 2, those read from the outside store. It reports entries after the newest seal as "not sealed yet".

Rows written before this change are chained once, in `id` order, the first time the new service starts; their payload is serialised from the columns then and stored, and has no `reportedBy`. The verifier treats them like any other entry.

### 6. Part 2: every seal is also written to a write-once store outside the database

After a seal is stored, it is pushed to a `SealStore`:

- **Production:** AWS S3 with Object Lock. Object key `seals/YYYY/MM/DD/<seq, 20 digits>.json`, so the newest seal is found by listing today's prefix and stepping back a day at a time (S3 lists in ascending order only; at one seal per 10 s a year is about 3 million objects). Written with `IfNoneMatch: "*"`, so a seal is never overwritten. Retention mode and period are configuration: `COMPLIANCE` and 365 days in production (matching DPDP's one-year retention; nobody, including the account root, can delete before then), `GOVERNANCE` and a short period for tests.
- **Development:** a local folder, written once (exclusive create).

Pushing is separate from signing: a seal stored but not yet pushed is retried, oldest first, on every tick. The service reports how far the outside copy lags. `custos audit-log` reads the newest outside seal, verifies the log against it, and warns when that seal is older than a configured limit, because the newest lines are only as safe as the newest outside seal.

IAM: the audit service gets `s3:PutObject` on the seal prefix only (no `DeleteObject`, `PutObjectRetention` or `BypassGovernanceRetention`); auditors get `s3:ListBucket` and `s3:GetObject`. `@aws-sdk/client-s3` is a new dependency, needed for exactly these calls; it sits behind the `SealStore` interface beside `@custos/kms`.

## Part 1, as built (2026-10-27)

- `packages/core/src/audit/ledger.ts`: `computeAuditPayloadHash`, `computeAuditEntryHash`, `serializeAuditRecord`, `issueAuditSeal`, `verifyAuditSeal`, `verifyAuditLedger`. `AuditRecord` gains `reportedBy`; `isAuditRecord` is exported; the per-record `issueAuditRecord`/`verifyAuditRecord` are removed.
- `services/audit`: migration `0010` (new nullable columns, unique `seq` and `prev_hash`, table `audit_seals`); `append.ts` (advisory lock, no network call), `chainUnchainedRecords` at boot, `list.ts`, `seal.ts`; `AUDIT_KEY_PROVIDER`, `AUDIT_SIGNING_SEED`, `AUDIT_SIGNING_KMS_KEY_ID`, `AUDIT_SEAL_INTERVAL_MS`; `buildServer` requires `signingKey`; `app.auditLedger.sealOnce()`.
- `@custos/audit-client` `pullAuditLedger`: fetches the DID document and the ledger and verifies them against the served seal and the caller's held seals for that log. `custos audit-log` remembers the newest verified seal per log in `~/.custos/audit-seal.json` (`--seal-file`) and never steps back to an older one; an unreadable file is an error, not a fresh start.
- `GET /records` reads the newest seal **before** the entries: the log only grows and a seal only covers committed entries, so the entries always include the sealed one. The other order let a seal made between the two reads cover an entry the response lacked, which an auditor would read as `TRUNCATED`. A test runs an append and a seal exactly between the two reads; the old order fails it every time.
- The dashboard reads `entries[].payload` and does not verify (as before). Checked in headless Chrome against `pnpm demo`: the live feed renders from the ledger.
- A sealing failure (KMS unreachable) is logged to the service's logger, which is silent by default, and shows only as a growing `unsealedCount`. Part 2 reports how far sealing and the outside copy lag.
- Run live against `pnpm demo` (2026-10-27): register, grant, an agent call; `custos audit-log` verified 92 entries against seal 92, each naming its reporter (`demo-dev-revocation`, `demo-dev-identity`, `demo-dev-vault`); editing entry 92 in Postgres made it exit 1 with `PAYLOAD_MISMATCH`, and restoring the entry made it pass again.

## Part 2a: the outside copy on a separate Postgres server first (founder, 2026-10-27)

S3 Object Lock (§6) stays the target. Until it is connected, every seal is copied to a **separate Postgres server**, the "seal store", behind the same `SealStore` interface S3 will implement. The founder chose this to avoid an AWS bucket that cannot be removed early.

- **Separation.** The seal store runs as its own server (a second container in development, port 5434), not a database on the audit server. Its one table, `audit_seal_copies (log, seq, seal, stored_at)`, primary key `(log, seq)`, is created by `infra/seal-store/schema.sql` and owned by an admin role. The audit service connects as `custos_sealer`, granted `INSERT` and `SELECT` only. Auditors connect as `custos_auditor`, granted `SELECT` only. A non-owner cannot `DROP` the table or disable its triggers. As a backstop, triggers **raise an error** on `UPDATE`, `DELETE` and `TRUNCATE`.
- **Copying.** It runs in the sealer's timer only, so an unreachable seal store never blocks appends, sealing or reads. Every stored seal not yet copied is pushed oldest first. `audit_seals.pushed_at` records success. A copy is `INSERT … ON CONFLICT DO NOTHING` followed by reading the row back; a **different** seal already stored at the same `(log, seq)` is a hard error, evidence of tampering. `GET /health` reports the newest sealed and newest copied `seq`.
- **Checking.** `custos audit-log` reads the copies **directly from the seal store** (`CUSTOS_AUDIT_SEAL_STORE_URL`, environment only, since it holds a password). It reads them **before** the ledger: a copy made after the ledger was read would cover an entry the response lacks. It checks the ledger against every copy from the seal it remembered onward, or every copy on a first run, not just the newest. Otherwise the service's own identity could sign a new, higher seal over a rewritten log and copy it. If the store is configured but unreachable, the result is `verified: false`. If it is not configured, the output says `outsideSealsChecked: false`.
- **What it protects, and what not.** Someone with **audit-database access only** cannot remove copies, so deleting or rewriting copied history is detected. They can stop _future_ copies by editing `pushed_at` or deleting unpushed seals. Entries newer than the newest copy (up to one seal interval plus copy lag) remain unprotected. On a quiet log the verifier cannot tell "nothing happened" from "copying stopped", because seals are made only when the head moves. The **seal store's administrator** can delete copies, which brings the guarantee back down to part 1. That is the gap S3 Object Lock closes. The **audit service's identity** can add a forged higher seal, but checking every copy reports `DIVERGED`.

## Key rotation (found 2026-10-27; founder chose proper rotation)

**The bug.** Every `pnpm demo` run gives the audit service a new seal key under the same log DID. Seals made under an earlier key failed verification under the key the service published, so after a second demo run `custos audit-log` failed every time with `SEAL_INVALID`. This affected part 1 on `main` (through the remembered seal in `~/.custos/audit-seal.json`) and showed up when testing part 2a against the live seal store. The same thing happens in production whenever the KMS key ID or the seed is changed: **any change of seal key is a rotation**.

**Not the fix: skipping seals that fail under the current key.** The DID document is served by the audit service itself, so it is no source of key history. Someone in control of the service could publish a new key, and every earlier seal would quietly stop counting, which undoes the rewrite detection.

**Decision.**

- Seals are `custos-audit-seal+v2` and name the key that signed them (`key`, multibase). v1 seals are refused (`MALFORMED_SEAL`); they existed only in development.
- `verifyAuditLedger` takes the trusted keys as a required parameter. Each seal is first checked under the key it names (a failure is `SIGNATURE_INVALID`), then that key must be trusted (`UNTRUSTED_KEY`, naming it), then it must name the log.
- `custos audit-log` pins keys per log in its seal file. The first check of a log trusts the published key and pins it. Later, a different published key is `KEY_CHANGED`, nothing is remembered, and the person is told to check the key with the service's operator (`pnpm demo` prints it at start), not against the DID document, and to pass `--accept-key`. **Pinned keys are never dropped**, so seals made before a rotation stay checked under their own key, and a log rewritten under a newly accepted key is still `DIVERGED`. A first-time auditor meeting copies under a key it never trusted gets `UNTRUSTED_KEY` for each and must accept each one out of band.
- The audit service records the key that made each seal (migration `0012`), serves only the newest seal made by its current key (none, right after a rotation, until the head moves), never re-seals a position already sealed, and copies to the seal store only seals that **verify** under its current key (checked by signature, not by the recorded key, which anyone with database access could change). The rest are listed in `GET /seals/status` (`notCopyable`).

**Found in final review and fixed.** A seal by an untrusted key is set aside, not returned at once: the verifier checks the other seals first, so a log rewritten and sealed under a new key is reported `DIVERGED` (or `TRUNCATED`), not as a routine `KEY_CHANGED`. Each seal's signature is checked once by the audit service and the result remembered, with a pause every 50 checks; `GET /seals/status` verifies nothing and shows an error code, never the seal server's error text (which names its host). `--accept-key` is repeatable, not a list, so an agent DID after it is not read as a key.

**Consequences.** Restoring the audit database from a backup is reported as `TRUNCATED` against the seal copies; that is intended, since a restored log has lost entries. Resetting the audit database while keeping the seal server makes copying stop on the first clashing position (`SEAL_CONFLICT`); reset both together. Seals made under an old key and not copied before the rotation stay uncopied for good, so before rotating in production, `copiedThrough` should equal `sealedThrough`. Old seal files from part 1 are refused with a message to remove them. After each `pnpm demo` restart, the first `custos audit-log` asks once for `--accept-key`.

ADR 0017 is accepted when part 2a merges. Part 2b (S3) is recorded as a follow-up.

## What each attacker can do

- **Database access only:** can change or delete entries, but any change to sealed history is detected (`DIVERGED` or a broken chain), and deleting the newest sealed entries is detected against the outside seal (`TRUNCATED`) from part 2. Before part 2, deleting the newest entries together with their seals goes unnoticed unless the verifier remembered a later seal. Entries newer than the newest outside seal (up to one interval plus push lag) can be deleted unnoticed.
- **The audit service's own AWS identity** (it holds `kms:Sign` and `s3:PutObject`): can add false new entries and seal them, but cannot remove outside seals, so it cannot erase or rewrite sealed history without the verifier reporting `DIVERGED` or `TRUNCATED`.
- **A reporting service** (`audit:write`): can report false events, but they carry its identity (`reportedBy`).

## Consequences

- Record format change: `GET /records` returns `{ entries, seal }` instead of individually signed records. `issueAuditRecord`/`verifyAuditRecord` are replaced by the ledger functions; the CLI, the dashboard and the tests that read records move with them.
- Every way of starting the audit service needs the key setting (and, from part 2, a seal folder or bucket): both demos, the e2e setups, README, `.env.example`, `docs/readme-test.md`.
- An auditor checks the whole log, or one agent's entries plus the hashes of everyone else's, not a single record on its own.
- A seal names its log by the audit service's DID, so changing `AUDIT_DID_DOMAIN` starts a different log as far as verifiers are concerned: earlier seals answer `WRONG_LOG`. Treat it like a key rotation.
- Still not covered: retention and export tooling, and a database-level append-only trigger (tampering is detected by the chain rather than prevented).

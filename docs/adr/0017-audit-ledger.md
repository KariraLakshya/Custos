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

# The audit ledger

Every decision Custos makes, allowed or refused, and every operator action goes into the audit log. The log is kept as a **ledger**: it can be checked by anyone, and an edit, a deletion or a rewrite is detected.

## What an entry records

Each entry carries:

- the **agent** (its DID), or for an operator action the **principal**: which API key, or which person signed in with SSO;
- the **tool**, **action**, and the tool's declared **data categories**;
- the **policy** rule applied and the **decision** (allow or deny), with a reason;
- the **authority chain** for a delegated call, from the operator who granted the tool through each agent, with the signed hand-offs as evidence;
- **`reportedBy`**: the service that reported it, taken from that service's authenticated API key or certificate, not from what it claims.

Services report entries without waiting for an answer. No request waits on an audit write.

## The hash chain

Each entry is numbered (`seq` 1, 2, 3, …) and hashed together with the hash of the entry before it:

```text
hash = SHA-256("custos.audit.entry.v1" ‖ 0x00 ‖ seq ‖ previous hash ‖ SHA-256(payload))
```

Changing, removing or reordering any entry changes every hash after it. The database itself refuses two entries following the same one, so the chain cannot fork.

## Seals

Every `AUDIT_SEAL_INTERVAL_MS` (10 seconds by default), if the log has grown, the audit service **seals** the newest entry: it signs that entry's number and hash with its audit key. A seal vouches for every entry up to it. Sealing at most once per interval keeps signing cost flat however busy the log is, and appending an entry never waits on a signature.

The audit key comes from `AUDIT_SIGNING_SEED` in development, or AWS KMS. Keep the seed: a new seed is a new key.

## The outside seal store

Someone who can write to the audit database could delete the newest entries **and** their seals together. So every seal is also copied to a **seal store** the audit service can add to but cannot change:

- **Development:** a separate Postgres server (`pnpm dev` starts one on port 5434), written as an insert-only user.
- **Production:** an AWS S3 bucket with Object Lock in COMPLIANCE mode, where nobody, not even the bucket's administrator, can delete a copy during its retention. The audit service refuses to start if the bucket isn't set up that way.

`GET /seals/status` on the audit service shows how far sealing and copying have got.

## Checking it: `custos audit-log`

```bash
custos audit-log
```

The CLI fetches the entries and the newest seal and checks, offline:

1. every hash in the chain;
2. the seal's signature, against keys this machine trusts;
3. that the log matches the seal (`TRUNCATED` if the sealed entry is missing, `DIVERGED` if it differs);
4. that it matches the newest seal **this machine remembered** from its last check (kept in `~/.custos/audit-seal.json`), so a log rebuilt and re-sealed since then is caught;
5. with `CUSTOS_AUDIT_SEAL_STORE_URL` set, every seal copied to the outside store from the remembered one on;
6. every delegation chain in the log, re-verified against the identity service.

It prints the verified log as JSON and exits non-zero on any failure. Entries newer than the newest seal are reported as `unsealedCount`.

### When the key changes

Seals name the key that made them, and the CLI pins the keys it has accepted. After the audit service starts with a new key, `custos audit-log` stops with `KEY_CHANGED` until a person accepts the new key, after checking it with whoever runs the audit service (never against the service's own DID document, which the service controls):

```bash
custos audit-log --accept-key <key>
```

Accepted keys are kept, and seals made under each are still checked.

## What it does not protect

- Entries newer than the newest outside copy (one interval plus copy lag) can be deleted unnoticed.
- With the Postgres seal store, that server's own administrator can delete copies. With S3 Object Lock, nobody can during retention.
- A service holding `audit:write` can still report false events, but each carries that service's identity.
- Failed authentications and failed proofs are logged, not audited, so nobody can flood the evidence log.
- `GET /records` is open on `main`: anyone who can reach it can read agent DIDs, tools, decisions and operator names (for SSO operators, email addresses).

Sources: ADR 0006, ADR 0017.

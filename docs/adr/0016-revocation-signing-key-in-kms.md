# 0016: The revocation signing key, and the publisher's, can live in AWS KMS

**Status:** Proposed 2026-10-25 (founder chose this as the next work after Phase 6). Built on branch `feat/revocation-signing-kms`; accepted when the founder merges it. Resolves ADR 0012's "KMS later" and ADR 0014 open question 5.

## Context

The revocation service signs every tombstone and the status list credential. Since ADR 0012 its key comes from `REVOCATION_SIGNING_SEED`, a secret in the environment. ADR 0014 decided that the cross-company publisher (`custos-admin publish-status`) signs **as the revocation service**, with the same key, so A's own vault trusts the lists it publishes without any change. The publisher runs on an operator's machine, so the seed would have to be copied there too. Whoever reads either environment can sign a status list that leaves a revoked agent out. ADR 0014 therefore called the publisher "not production-ready until its key is in KMS".

The identity service already signs with AWS KMS (ADR 0007 decision 4), through a `KeyProvider` (ADR 0002) that lived inside `services/identity`.

## Decision

1. **One shared provider.** `createKmsKeyProvider` moves to a new package, `packages/kms` (`@custos/kms`). It is a package that is allowed to do I/O, not `packages/core`. It adds `createKmsClient()`, a client with bounded timeouts (2 s to connect, 5 s per request) and at most two attempts, so a slow KMS fails a signature within seconds instead of holding a revocation open. A stand-in for tests is at `@custos/kms/testing`. Identity uses it unchanged, apart from those bounds.
2. **Revocation: `REVOCATION_KEY_PROVIDER=local|kms`**, default `local`. `kms` needs `REVOCATION_SIGNING_KMS_KEY_ID`; `local` still needs the seed. A missing setting for the chosen provider is a boot failure, never a fallback. The public key is read at boot, so a wrong key ID or a missing permission stops the service before it serves.
3. **Publisher: `CUSTOS_PUBLISHER_KEY_PROVIDER=local|kms`**, default `local`, with `CUSTOS_PUBLISHER_KMS_KEY_ID` set to **the revocation service's key**. Two AWS identities need `kms:GetPublicKey` and `kms:Sign` on that one key: the revocation service's and the publishing operator's. Neither needs anything else. Nothing in Custos calls `CreateKey` (it bills a new key on every call); tests assert this.
4. **The open status-list route reuses its signature** (founder's choice, 2026-10-25). `GET /status/revocation` is open to anyone and used to sign a fresh list on every request. With a KMS key each signature is a billed, rate-limited network call on the key that also signs tombstones. Someone could request the list in a loop, use up the account's signing allowance, and so block real revocations. The service now serves the last signed list again while its contents are unchanged and it is younger than `REVOCATION_STATUS_REUSE_MS` (default 5 s). Requests that arrive while a signature is in progress share it. A revocation changes the contents and is signed at once, so reuse never delays a cut-off. A failed signature is never reused. The cost: the list's `validFrom` can lag by up to 5 s. With the vault's defaults (resync every 10 s, staleness bound 30 s) the worst case is about 15 s, inside the bound. Equal `validFrom` values are accepted by the vault: they simply don't move its freshness forward. This applies to the local key too, so behaviour does not depend on where the key lives.
5. **A KMS outage is a result, not a crash, in the publisher.** A local key never fails; KMS can. `publishOnce` reads the key first and returns `KEY_UNAVAILABLE` (retryable; `run` carries on) if KMS cannot be reached. The provider keeps the public key once read, so later reads cannot fail. A failed signature is the existing `SIGNING_FAILED`, also retryable. The journal (the record of truth) is written before any signature, so a KMS outage never loses a revocation. It is carried by the next publish that succeeds. `publish-status revoke` does not read the key before writing the journal: the list address comes from the domain alone, and an existing journal is enough to show the publisher was initialised. A revocation made during an outage is recorded and reported as `NOT_PUBLISHED` (`KEY_UNAVAILABLE`). An early review found that it used to throw before reaching the journal; tests now cover revoking by index and by credential while KMS is unreachable.

In the revocation service, a revocation's bit is written to the database before its tombstone is signed. A KMS failure during a revocation answers `502 SIGNING_FAILED` and the push is lost, but the agent stays revoked in the status list, which the vault resyncs from (ADR 0013). A test proves this.

## Verified against real AWS KMS (2026-10-25)

All of this ran in `ap-south-1`, profile `custo`, with a throwaway key created for the check and scheduled for deletion straight after (it deletes on 2026-11-01).

- `pnpm --filter @custos/kms test:kms`: 4 of 4 passed. The key reads as 32 raw bytes, and KMS signatures verify with `@custos/core` (and fail against another key). Signing is **deterministic**, so ADR 0013's tombstone memo still serves byte-identical tombstones. A KMS-signed agent credential verifies.
- `pnpm --filter @custos/admin test:kms`: 1 of 1 passed. A real revocation service on the KMS key published a DID document whose key equals the KMS key. Its tombstones and status list verify against that document. The publisher, configured with `CUSTOS_PUBLISHER_KMS_KEY_ID`, published a list that a foreign verifier anchored only on that DID document accepts. The largest message sent to KMS was 218 bytes, against KMS's 4096-byte limit for raw signing.
- `createKmsClient()` pointed at an address that never answers (`AWS_ENDPOINT_URL_KMS`) gave up after 4.1 s with `TimeoutError`: two attempts at the 2 s connection limit. The 5 s request limit, for a KMS that connects and then stalls, was not exercised.
- The built service (`node dist/index.js`):
  - With `REVOCATION_KEY_PROVIDER=kms` and no key ID, it refused to boot.
  - With a key ID that does not exist, it refused to boot (`NotFoundException`).
  - With the real key, it served a DID document whose key matched `aws kms get-public-key`, served a status list that verified, and served the same signed list to a second request.

## Consequences

- The production posture for revocation and the publisher is now the same as identity's: the private key never leaves KMS. The seeds remain for development, `pnpm demo` and `pnpm demo:federation` (both scrub `REVOCATION_*` and `CUSTOS_*` from the shell, so they always run on the local default).
- KMS is now on the revocation service's cold path. Every revocation costs one KMS call (about 100 ms measured), and so does each status list after a reuse window. With the 5 s window that is at most about 12 a minute however many requests arrive. The hot path is untouched: verifiers check signatures locally against the cached DID key.
- Key rotation is still an event, as ADR 0012 says. Switching an existing deployment from the seed to KMS **is** a rotation: subscribers re-resolve the did:web key, and the publisher refuses (`KEY_MISMATCH`) until the lists signed by the old key are retired. ADR 0014 already describes this.
- Granting `kms:Sign` to an operator's AWS identity lets that person sign any status list for the organisation, the same power the seed gave. The difference is that it can be revoked in IAM, every use is logged by AWS CloudTrail, and it cannot be copied.
- Still not in KMS: the vault's token key and the audit signing key (both ephemeral; unchanged, see `docs/threat-model.md` §5).

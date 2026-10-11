# 0012: The revocation signing key survives restarts

**Status:** Accepted, 2026-10-11.

## Context

`services/revocation` signs every tombstone and the status list credential with a key that was generated in memory on each start. Every subscriber resolves that key from the service's did:web document and caches it. After a restart the cached key is wrong, so the vault re-resolves it and re-verifies every tombstone ever issued (the fail-open bug found on 2026-10-08, and the resync cost measured on 2026-10-11).

Identity solved the same problem for its issuer key in ADR 0007 decision 4.

## Decision

The key comes from configuration and outlives the process. `REVOCATION_SIGNING_SEED` (32 bytes, 64 hex characters) is **required, with no default**: the service refuses to boot rather than fall back to a known or ephemeral key. The seed feeds `createLocalKeyProvider({ importedKeys })`, the mechanism identity already uses. `buildServer` requires a `signingKey` and reads only the public key from it (`getPublicKey`); a provider's `createKeyPair()` would mint a fresh random key and ignore the seed.

Ed25519 signing is deterministic and a tombstone contains only database fields, so a restarted service serves byte-identical tombstones. The vault's memory of verified tombstones (PR #65) then keeps hitting across restarts.

## Consequences

- Changing the seed is a key rotation. Subscribers follow it through the existing did:web re-resolution, and one full re-verify happens. Treat it as an event, not a routine restart.
- The seed is a secret in the environment, the same posture as `IDENTITY_ISSUER_SEED`. It is not in a KMS yet. This is dev-grade custody for a key that can revoke any agent, recorded in `docs/threat-model.md`.
- Every way of starting revocation must now set the seed. README, `.env.example` and the tester brief are updated; tests inject a key.
- **KMS later.** `services/identity/src/keys/kms-key-provider.ts` would need to move out of the identity service, into a shared package that is allowed to do I/O (not `packages/core`, which is pure). A `REVOCATION_KEY_PROVIDER=local|kms` switch with `local` as the default can be added then without breaking anyone, so it is not added now.
- The audit service's signing key is still ephemeral. It does not have this problem, because audit rows are signed at read time, but it is the same kind of debt.

# 0004: Vault credential encryption at rest — KMS-shaped `SecretCipher`

## Context

Phase 2's vault stores real third-party tool credentials (a Stripe test-mode secret key, in the first instance) server-side in Postgres. CLAUDE.md section 4 doesn't name this specific case, but its governing principles apply directly: private key material never touches disk in plaintext, and a KMS-shaped interface is used from the first real credential rather than a plaintext store meant to be migrated later ("the migration window is itself the vulnerability"). A tool credential is not a signing key, but it is exactly the kind of long-lived secret that rule exists to protect — leaking it is strictly worse than leaking a signing key, since it's directly usable against the real third-party API with no cryptographic step in between.

## Decision

`packages/core/src/keys/secret-cipher.ts` defines a `SecretCipher` interface (`encrypt(plaintext) -> {ciphertext, nonce}`, `decrypt({ciphertext, nonce}) -> plaintext`), structurally the same shape as `KeyProvider`: callers never see the key. `local-secret-cipher.ts` implements it with XChaCha20-Poly1305 from `@noble/ciphers` (same audited-crypto family already in use, extending CLAUDE.md section 5's `@noble/*`-only rule to symmetric encryption), keyed by a 32-byte key injected at construction — sourced from `services/vault`'s `VAULT_MASTER_KEY` env var (validated at startup per CLAUDE.md section 7), never generated or persisted by the cipher itself.

XChaCha20-Poly1305 over AES-GCM: no hardware AES acceleration dependency, a 24-byte random nonce large enough to generate per-encryption without a collision-counting scheme, and it's already one of `@noble/ciphers`' primary supported constructions.

`services/vault` stores `{tool, ciphertext, nonce}` rows; the plaintext credential exists only transiently, decrypted in-memory at the moment a scoped token is redeemed (`POST /call`), passed directly to the connector, and never logged (CLAUDE.md section 4).

## Consequences

- `VAULT_MASTER_KEY` is a single symmetric key for all stored tool credentials in this phase — not per-tool, not envelope-encrypted. Acceptable for a dev/demo deployment; a real deployment replaces `createLocalSecretCipher` with an AWS KMS-backed `SecretCipher` doing envelope encryption (KMS wraps a per-record data key), with zero change to `services/vault`'s call sites — the interface point is already correct.
- Losing `VAULT_MASTER_KEY` makes every stored credential permanently unrecoverable (AEAD, no key recovery). Rotating it requires re-encrypting all stored rows; not needed at this phase's scale (a handful of tool credentials) and not built now (CLAUDE.md section 2, scope discipline).
- Tampered ciphertext (bit-flipped in the database, or a nonce/ciphertext mismatch) is caught by AEAD authentication and fails `decrypt` closed rather than returning corrupted plaintext to a connector.

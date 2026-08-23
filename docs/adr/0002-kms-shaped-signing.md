# 0002: KMS-shaped signing — inject a signer, never a secret key

## Context

Phase 0's `issueCredential` (`packages/core/src/vc/credential.ts`) took a raw `secretKey: Uint8Array` and reconstructed an `Ed25519VerificationKey2020` key pair from it internally to drive the `jsonld-signatures` suite. Its own doc comment flagged this as temporary: "Phase 1 replaces this with a KMS-shaped signer that never exposes `secretKey` to this function at all" — matching CLAUDE.md section 4's rule that signing goes through a KMS-shaped interface from the first real credential, with a local implementation behind the same interface, never a plaintext key store meant to be migrated later.

Phase 1 introduces a per-agent `KeyProvider` (`packages/core/src/keys/key-provider.ts`): `createKeyPair()` returns a public key and an opaque `keyId`, `sign(keyId, message)` returns a signature — the private key never leaves the provider. `issueCredential` needed to accept whatever that provider can hand out, which is a signing capability, not key material.

## Decision

`issueCredential` now takes an injected `signer: { id: string; sign(input: { data: Uint8Array }): Promise<Uint8Array> }` instead of `secretKey`. This is not a new abstraction invented for this purpose: `jsonld-signatures`' `LinkedDataSignature` base class (via `Ed25519Signature2020`) already supports constructing the suite with `{ signer }` instead of `{ key }` — explicitly documented upstream as "useful when interfacing with a KMS (since you don't get access to the private key... the KMS client gives you only the signer function to use)." Confirmed by reading the installed library's source (`node_modules/.pnpm/jsonld-signatures@11.6.0/.../LinkedDataSignature.js`) before relying on it.

`services/identity`'s registration flow wires a `KeyProvider` into this signer shape: `{ id: verificationMethodId, sign: (input) => keyProvider.sign(keyId, input.data) }`. `packages/core` never sees `secretKey` during issuance at all — not "doesn't need to," structurally cannot.

## Consequences

- `issueCredential`'s test suite (`credential.test.ts`) now builds signers via a local `signerFor(secretKey, verificationMethodId)` helper instead of passing `secretKey` directly; behaviorally unchanged, all prior negative-test coverage (tampered credential, unknown verification method, wrong key type, malformed key material) is preserved.
- The one test that could no longer apply as written ("fails closed on a malformed secret key") is replaced with "fails closed when the injected signer rejects" — the equivalent failure mode now sits at the signer boundary, not inside `issueCredential`.
- `packages/core`'s ambient type declarations for `@digitalbazaar/ed25519-signature-2020` (`types/vc-libs.d.ts`) were widened to declare the `signer` constructor option, matching the library's actual (untyped) JS surface.
- Any future KMS-backed `KeyProvider` implementation plugs into `issueCredential` with zero changes to `packages/core` — the interface point was already correct, this just stops bypassing it.

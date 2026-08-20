# 0001: Verifiable Credential proof format — JSON-LD Data Integrity via existing libraries

## Context

Phase 0 requires issuing and verifying one W3C Verifiable Credential (VC Data Model 2.0). The VC spec supports two proof formats: JSON-LD Data Integrity proofs (canonicalize the credential's RDF graph with URDNA2015, then sign the canonical form) or VC-JWT (skip RDF entirely, sign a JWT-encoded claims set).

The JSON-LD path is the one with actual design value for Custos: the audit and delegation-provenance work in section 10 of `CLAUDE.md` depends on credentials whose fields carry unambiguous, extensible semantics (a `@context`-defined vocabulary), which is what JSON-LD gives and a bag of JWT claims does not.

Implementing JSON-LD Data Integrity correctly requires an RDF Dataset Canonicalization (URDNA2015) implementation. This is the one part of the stack with a real, non-obvious failure mode: a canonicalizer bug doesn't crash, it silently produces a wrong-but-valid-looking canonical form. Two credentials that should differ could canonicalize identically (a forgery vector), or the same credential could canonicalize differently across two implementations (valid credentials failing verification for no real reason, discovered in production, not in a test).

## Decision

Use the existing Digital Bazaar library stack rather than implement URDNA2015 or JSON-LD signing ourselves:

- `jsonld` / `jsonld-signatures` — JSON-LD processing and the sign/verify orchestration (`ProofSet`, proof purposes).
- `@digitalbazaar/ed25519-verification-key-2020` / `@digitalbazaar/ed25519-signature-2020` — the Ed25519Signature2020 Data Integrity cryptosuite. On Node, this key library signs/verifies through `node:crypto`'s native Ed25519 (OpenSSL), not a hand-rolled implementation.
- `@digitalcredentials/credentials-v2-context`, `ed25519-signature-2020-context`, `@digitalbazaar/security-context` — bundled, static JSON-LD `@context` documents (VC Data Model 2.0, the Ed25519Signature2020 suite, and the general security vocabulary).
- `base58-universal` — trivial multibase encoding (multicodec-prefix + base58btc) for `did:web` documents; not a cryptographic operation, just a format also used internally by the Digital Bazaar key library.

All are actively maintained (2025–2026 releases) and Node 22-compatible.

**Document loader is fully static, bundled at build time, never network-fetching.** `packages/core/src/vc/document-loader.ts` resolves only the three bundled context URLs above and throws on anything else. This matters for two independent reasons: it keeps `packages/core` free of I/O (the architecture invariant in `CLAUDE.md` section 3), and it closes a real JSON-LD signature verifier vulnerability class — a malicious credential smuggling in an attacker-controlled `@context` URL that the verifier would otherwise fetch.

**Verification always supplies an explicit `key`, never resolves it through the document loader.** `@digitalbazaar/ed25519-signature-2020`'s `getVerificationMethod` only falls back to fetching the verification method via the document loader when no `key` is given at suite construction; that fallback path was found to have a Multikey-context mismatch in the installed version combination (`Ed25519Multikey.from()` rejecting the framed verification method). Rather than work around a library-version quirk, `verifyCredential` looks up the matching `verificationMethod` in the caller-supplied, already-resolved DID document and passes it to the suite directly — which is also the architecturally correct choice: CLAUDE.md section 3 requires verification to be local and not depend on live issuer resolution, and the caller is responsible for having already resolved and cached the DID document.

## Consequences

- Nine new dependencies in `packages/core` (listed above). Each is single-purpose: three are static context bundles forced by JSON-LD's context-dereferencing design, not bloat; two wrap the signing suite; the rest are orchestration/encoding primitives.
- Every field used in a credential's `credentialSubject` must be defined by a loaded `@context` (either a bundled one or an inline context object on the credential itself) — JSON-LD's safe-mode expansion drops or errors on undefined properties. This is a real constraint on future credential shapes, not a bug.
- No TypeScript types exist upstream for most of these packages. `packages/core/src/types/vc-libs.d.ts` carries minimal ambient declarations scoped to the exact surface used here.
- `packages/core` gains its first genuine "spec-shaped but library-implemented" primitive; the pattern (bundle static contexts, never fetch, always pass explicit keys) should be reused rather than re-derived if later phases add more credential types.

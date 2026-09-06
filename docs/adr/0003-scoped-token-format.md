# 0003: Scoped token format — custom compact Ed25519 token, not JWT

## Context

Phase 2 needs the vault to hand a verified agent a short-lived (60s default), tool-and-action-scoped access token (CLAUDE.md section 4). That token must be verifiable entirely locally, with no network or database call (CLAUDE.md section 3, "verification is local and offline-capable" — this is the hot path: every tool call checks one of these).

The standard answer is a JWT. That pulls in a JOSE/JWT library (`jose`, `jsonwebtoken`, or similar) purely to produce `base64url(header).base64url(payload).base64url(signature)` with a signature algorithm we already have in-house — CLAUDE.md section 4: "dependencies are attack surface... prefer a primitive over a convenience wrapper," and section 5 restricts crypto to `@noble/*`. A JWT library also brings header/algorithm negotiation (`alg: none`, algorithm confusion between HMAC and asymmetric) that is a real source of JWT-specific vulnerabilities and buys nothing here: there is exactly one algorithm (Ed25519) and exactly one issuer (the vault), never negotiated.

## Decision

`packages/core/src/token/scoped-token.ts` defines a minimal compact format: `base64url(JSON(claims)) + "." + base64url(signature)`, where `signature` is an Ed25519 signature (via the existing `@noble/ed25519`-backed `crypto/ed25519.ts`) over the UTF-8 bytes of the base64url-encoded claims. Claims are `{ sub, tool, action, iat, exp }` — no header, no algorithm field, nothing to negotiate. Issuance takes an injected KMS-shaped `signer` (mirroring `vc/credential.ts`'s `CredentialSigner`), never a raw secret key. Verification takes a caller-supplied public key and an injected `now: Date` (CLAUDE.md section 3: no clock reads outside an injected dependency) and fails closed on malformed structure, a bad signature, or expiry.

## Consequences

- No new JOSE/JWT dependency; the only crypto primitive in play is the same Ed25519 code path already used and tested for VC signatures.
- The format is deliberately not JWT-compatible. That is fine: nothing outside Custos ever needs to parse this token, and the vault is both sole issuer and sole verifier today.
- If a future phase needs a second, independent verifier for these tokens (e.g. connectors running as separate processes, or cross-org federation in Phase 6), the public key must be distributed to it the same way DID documents already are — this format carries no `kid`/issuer field to do that lookup itself, so that verifier needs to be told which vault instance's key to check. Not needed yet; scope discipline (CLAUDE.md section 2) says don't build it now.
- Because `exp`/`iat` are unix seconds, not milliseconds, tokens stay short; the tradeoff is one-second expiry granularity, immaterial at a 60-second TTL.

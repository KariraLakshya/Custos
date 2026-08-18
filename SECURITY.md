# Security Policy

Custos is a security product. Please report vulnerabilities responsibly.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Instead, email the maintainer at lakshya@capmobfinance.com with:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept
- Any relevant logs (redact secrets before sending — see below)

We aim to acknowledge reports within 3 business days.

## Non-negotiable security rules for contributors

These are enforced in review and in CI, not by convention:

- Private signing keys never touch disk, logs, or version control.
- Secrets, tokens, and key material are never logged. Redaction is enforced in the logging package itself.
- Agents never receive raw, long-lived tool credentials.
- Tokens are short-lived and scoped.
- Only audited cryptography (`@noble/*`) is used — no hand-rolled crypto.
- Expiry and revocation checks are mandatory and cannot be bypassed by configuration.
- Every security control (tampered credential, expired token, revoked agent, unknown signer, malformed input, out-of-scope access) has a negative test in CI.

See [CLAUDE.md](./CLAUDE.md) §4 for the full list.

## Supported versions

Pre-1.0; no version support guarantees yet. `main` is the only supported branch.

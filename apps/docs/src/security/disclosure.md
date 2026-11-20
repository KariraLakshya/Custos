# Reporting a vulnerability

Custos is a security product. Please report vulnerabilities responsibly.

- **Do not open a public issue** for a suspected vulnerability.
- Email the maintainer at the address in [`SECURITY.md`](https://github.com/KariraLakshya/Custos/blob/main/SECURITY.md), with a description of the issue and its impact, steps to reproduce or a proof of concept, and any relevant logs, **with secrets removed**.
- Reports are acknowledged within 3 business days.

Custos is pre-1.0. There are no version support guarantees yet; `main` is the only supported branch.

## Rules every change follows

These are enforced in review and in CI, not by convention:

- Private signing keys never touch disk, logs or version control.
- Secrets, tokens and key material are never logged. Redaction is enforced in the logging package itself.
- Agents never receive raw, long-lived tool credentials.
- Tokens are short-lived and scoped.
- Only audited cryptography (`@noble/*`) is used: no hand-written cryptography.
- Expiry and revocation checks are mandatory and cannot be switched off by configuration.
- Every security control has a negative test in CI: a tampered credential, an expired token, a revoked agent, an unknown signer, malformed input and out-of-scope access are each proven to fail.

CI also runs `pnpm audit`, Gitleaks secret scanning and Semgrep on every pull request and weekly.

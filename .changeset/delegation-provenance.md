---
"@custos/sdk": minor
"@custos/cli": minor
---

Delegation provenance (ADR 0020): an agent can pass part of its access to another agent with a signed hand-off. SDK: `delegate()` and `connect(agent, tool, { delegation })`. CLI: `custos delegate`, `custos use --delegation`, and `custos audit-log --identity-issuer`, which re-verifies every delegation chain in the audit log offline. Refusals now print their reason.

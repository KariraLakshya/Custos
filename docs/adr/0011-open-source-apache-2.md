# 0011: Open source under Apache-2.0

**Status:** Accepted, 2026-10-08. The founder chose to open-source Custos now and to use Apache-2.0, after weighing it against AGPL-3.0 and MIT.

## Context

The licence decision had been deferred since the scaffold (`docs/state.md`): no `LICENSE` file, every package `"license": "UNLICENSED"`. Custos is now positioned as an early-stage, open-source developer platform for AI agents, building toward a hosted trust service. Calling it open source requires an actual open-source licence.

## Decision

- The repository is licensed under the **Apache License, Version 2.0**: the canonical text in `LICENSE`, a `NOTICE` file ("Copyright 2026 The Custos Authors"), and `"license": "Apache-2.0"` in the root and every package manifest.
- Packages stay `"private": true`. Choosing a licence isn't publishing: nothing goes to npm until a release target is decided separately.

**Why Apache-2.0:**

- It's the norm for security and infrastructure software, and the licence corporate legal teams approve most readily. Adoption by developers and companies matters more at this stage than protecting the code.
- It has an explicit patent grant and patent-retaliation clause, which MIT lacks. That matters for a cryptography-adjacent product that companies will build on.

**Alternatives rejected:**

- **AGPL-3.0** would require anyone offering a modified Custos as a hosted service to publish their changes, protecting a future hosted offering from resellers. Rejected because many companies forbid AGPL dependencies, which would cut adoption of the SDK and connectors.
- **MIT** gives the same hosting exposure as Apache-2.0 without the patent grant.

## Consequences

- Anyone, including a competitor, may run, modify, or host Custos, provided they keep the licence and `NOTICE`. A hosted offering will have to win on operation, trust and features, not on exclusive access to the code.
- **Relicensing later is hard.** Code released under Apache-2.0 stays available under it. Moving to a more restrictive licence would cover only new code and would need every contributor's agreement, or a CLA, for existing code. If outside contributions start, decide on a CLA or DCO first.
- `SECURITY.md`'s private disclosure route matters more once the code is public.
- **Making the GitHub repository public is a separate, manual step** for the founder. This ADR licenses the code; it doesn't publish it. Before going public, check the git history for anything that shouldn't be public: Gitleaks runs in CI, and `docs/state.md` records identifiers such as an AWS profile name and an IAM user name, not secrets.

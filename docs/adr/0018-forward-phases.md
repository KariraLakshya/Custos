# 0018: Forward phases — packaging, delegation provenance, sidecar, eBPF, Kubernetes

**Status:** Proposed 2026-10-30 (founder chose the order on 2026-10-28). Accepted when the pull request adding it merges. The phases themselves are in `docs/build-plan.md` (Phases 7–11).

## Context

After ADR 0017 the build plan had no further phase. Its "Later" list held the sidecar and eBPF enforcement as demand-pulled, and `CLAUDE.md` §2 forbids building the sidecar, eBPF and Kubernetes manifests until the build plan's current phase calls for them. On 2026-10-28 the founder decided the next work, in this order: packaging (container images, CI brings the stack up from images only), delegation provenance, the sidecar, eBPF, then Kubernetes.

## Decision

Add five phases to `docs/build-plan.md`, each with a DONE line provable in CI and a "Not in this phase" line:

| Phase | Work                    | Where it comes from                                                                                                                   |
| ----- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 7     | Packaging               | New. Nothing in the plan covered images; the stack ran only from source.                                                              |
| 8     | Delegation provenance   | `CLAUDE.md` §10 (authority chain in every audit record, DPDP). It was a design direction, never a phase, and not on the "Later" list. |
| 9     | Sidecar                 | Pulled from "Later".                                                                                                                  |
| 10    | eBPF egress enforcement | Pulled from "Later".                                                                                                                  |
| 11    | Kubernetes              | Taken off `CLAUDE.md` §2's do-not-build list. It was not on the "Later" list.                                                         |

Ordering consequences, accepted:

- **The sidecar and eBPF come before Kubernetes**, so their DONE lines are proven without pods: the sidecar under Compose (agent and sidecar sharing one network namespace), eBPF on a CI Linux runner. Kubernetes then packages what already works.
- **eBPF cannot be TypeScript.** Phase 10 starts with an ADR choosing the language and loader. That ADR revisits `CLAUDE.md` §5's "Rust for the enforcement engine is … not now".
- **The development machine is Windows**, so eBPF's DONE is CI-only. Local runs need WSL2 or a Linux machine.

What stays on "Later": hot/cold split beyond the sidecar, the structured data proxy, content inspection, hosted and TEE modes, protocol publication. "Open-source release" is removed from it: the repository is already public under Apache-2.0 (ADR 0011).

This ADR records scope and order only. Each phase's design choices (image base and pruning, delegation format, sidecar protocol, eBPF language, manifest format) get their own ADR when that phase starts.

## Consequences

- `CLAUDE.md` §2's list is unchanged: it already defers to the build plan's current phase. Each item becomes buildable only when its phase is current.
- Phase 5's DONE check (non-author README run) is still owed. Phase 7 makes it easier: a tester needs Docker only.
- `docs/build-plan.drawio` does not show Phases 7–11 yet (recorded in `docs/state.md` Known issues).

## Decided questions

1. **Publish images?** Decided by the founder 2026-10-30: **not in Phase 7.** Images are built and tested in CI only. Publishing release images to a public registry (for example GitHub Container Registry) is recorded for later, to be revisited at launch alongside ADR 0017 part 2b's deferred real-AWS proof.

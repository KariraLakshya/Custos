# instructions.md

Behavioral guidelines to reduce common LLM coding mistakes. Project-specific rules live in `CLAUDE.md`; where they conflict, see section 5.

**Tradeoff:** these guidelines bias toward caution over speed. For trivial tasks, use judgment.

---

## 1. Think before coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

---

## 2. Simplicity first

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for genuinely unreachable code paths.
- If you write 200 lines and it could be 50, rewrite it.

Ask: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

---

## 3. Surgical changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:

- Remove imports, variables, and functions that _your_ changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the request.

---

## 4. Goal-driven execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

## 5. Reconciliation with CLAUDE.md

These guidelines are general; `CLAUDE.md` is specific to this project. Three places they appear to conflict, and how to resolve them.

**Mandated abstractions are requirements, not speculation.** Section 2 forbids speculative abstraction. It does not override an interface that `CLAUDE.md` or an ADR explicitly requires — the `KeyProvider` interface, the pure boundary around `packages/core`, the connector interface. These exist for stated security and architectural reasons. Build them as specified. What section 2 forbids is abstraction _you_ invent because it might be useful later.

**Defensive validation on trust boundaries is always required.** Section 2's "no error handling for unreachable paths" applies to internal logic, never to a security boundary. On any path handling a credential, token, external payload, or tool response, validate explicitly even when malformed input seems impossible — malformed credentials, oversized payloads, and unexpected types are exactly the inputs that look unreachable until someone sends them. `CLAUDE.md` requires negative tests for these; the handling they test must exist.

**Test code is exempt from minimalism.** Section 2's brevity preference does not apply to tests. `CLAUDE.md` mandates unit, integration, end-to-end, and contract layers plus security negative cases, with coverage gates. Thorough tests are not overcomplication. Never reduce test coverage to satisfy a simplicity heuristic.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions arriving before implementation rather than after mistakes.

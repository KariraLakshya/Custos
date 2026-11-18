# Refusal codes

When Custos says no, it answers with a code. The `custos` CLI turns each code into three lines: what happened, what to do next, and the code itself, for scripts and for searching this page.

```text
Refused: This agent has not been given this tool.
Next: To allow it, an operator runs: custos grant mock-database --to <agent id>
Code: POLICY_DENIED
```

- **Refused** means Custos is working as intended: the request was not allowed.
- **Problem** means something is actually wrong, such as a service that is down or a key that cannot be used. The catalogue calls these `alarm`.
- Some codes carry a finer **reason** after them, as in `Code: DELEGATION_DENIED (NOT_COVERED)`. Those are listed in their own tables below.

This page is generated from the refusal catalogue in `packages/contracts/src/refusals.ts` every time the site is built, so it always matches what the CLI prints. The SDK exposes the same catalogue: `refusalFor(code, reason)` from `@custos/contracts`. `<tool>` and `<agent>` in a next step are filled in by the CLI from the command you ran.

<!-- @custos-refusals -->

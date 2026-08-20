// Structurally identical to @custos/contracts' Result, but defined locally:
// packages/core depends on nothing else in the workspace, by architecture
// invariant (see CLAUDE.md section 3), so it cannot import from contracts.
export type Result<T, E> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: E };

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

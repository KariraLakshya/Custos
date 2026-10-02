// Test-only clocks. Local rather than from @custos/testing, which depends on
// this package for its control-plane test helpers (no workspace cycle).
export function fixedClock(at: Date | string): { now(): Date } {
  const fixed = new Date(at);
  return { now: () => new Date(fixed.getTime()) };
}

export function mutableClock(at: Date | string): { now(): Date; set(next: Date | string): void } {
  let current = new Date(at);
  return {
    now: () => new Date(current.getTime()),
    set: (next) => {
      current = new Date(next);
    },
  };
}

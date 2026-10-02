export interface Lockout {
  isLocked(source: string): boolean;
  recordFailure(source: string): void;
}

interface Entry {
  windowStart: number;
  failures: number;
  lockedUntil: number;
}

/**
 * Brute-force protection (ADR 0008 §8): after `maxFailures` failed
 * authentications from one source within `windowMs`, that source is refused
 * for `lockMs`. In memory, per service instance, like the vault's replay
 * cache — correct for one instance; scaling out needs a shared store.
 *
 * Bounded at `maxSources`: past it, the oldest entry is dropped. A flood
 * from many addresses can therefore evict a lock early, but can't exhaust
 * memory; the keys themselves (256 random bits) are the real defence.
 */
export function createLockout(options: {
  readonly clock: { now(): Date };
  readonly maxFailures?: number;
  readonly windowMs?: number;
  readonly lockMs?: number;
  readonly maxSources?: number;
}): Lockout {
  const maxFailures = options.maxFailures ?? 10;
  const windowMs = options.windowMs ?? 5 * 60_000;
  const lockMs = options.lockMs ?? 15 * 60_000;
  const maxSources = options.maxSources ?? 10_000;
  const entries = new Map<string, Entry>();
  const now = (): number => options.clock.now().getTime();

  return {
    isLocked(source) {
      const entry = entries.get(source);
      return entry !== undefined && entry.lockedUntil > now();
    },

    recordFailure(source) {
      const at = now();
      let entry = entries.get(source);
      if (!entry || (entry.lockedUntil <= at && at - entry.windowStart >= windowMs)) {
        entry = { windowStart: at, failures: 0, lockedUntil: 0 };
      }
      entry.failures += 1;
      if (entry.failures >= maxFailures) {
        entry.lockedUntil = at + lockMs;
        entry.windowStart = at;
        entry.failures = 0;
      }
      // Re-insert so Map order tracks recency; evict the oldest past the bound.
      entries.delete(source);
      entries.set(source, entry);
      if (entries.size > maxSources) {
        const oldest = entries.keys().next().value;
        if (oldest !== undefined) entries.delete(oldest);
      }
    },
  };
}

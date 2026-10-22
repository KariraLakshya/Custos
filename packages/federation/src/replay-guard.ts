import type { ForeignReplayGuard, ReplayVerdict } from "@custos/core";

/**
 * Remembers proof ids until the proof would be stale anyway, so a captured
 * proof cannot be replayed (ADR 0014). In memory, so correct for one verifier
 * process only: several instances need a shared store behind the same
 * `ForeignReplayGuard` interface. After a restart it is empty, which is safe
 * because proofs older than the skew window are refused on their own.
 *
 * "full" means no room without forgetting a live id, so the call is refused:
 * failing closed beats forgetting what was used.
 */
export function createInMemoryReplayGuard(options?: {
  readonly maxEntries?: number;
}): ForeignReplayGuard {
  // Only proofs whose signature verified are recorded (core checks that first),
  // and each lives about two skew windows, so this bound is generous.
  const maxEntries = options?.maxEntries ?? 100_000;
  const expiries = new Map<string, number>();

  function pruneExpired(nowMs: number): void {
    for (const [key, expiresAtMs] of expiries) {
      if (expiresAtMs < nowMs) expiries.delete(key);
    }
  }

  return {
    record(key, expiresAtMs, nowMs): ReplayVerdict {
      const existing = expiries.get(key);
      if (existing !== undefined && existing >= nowMs) return "replayed";
      if (expiries.size >= maxEntries) {
        pruneExpired(nowMs);
        if (expiries.size >= maxEntries) return "full";
      }
      expiries.set(key, expiresAtMs);
      return "fresh";
    },
  };
}

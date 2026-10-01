/**
 * Remembers proof-of-possession ids (`jti`) until the proof would be stale
 * anyway, so a captured proof can't be replayed (ADR 0007 decision 3). An
 * interface so a shared store (Redis) can back it once the vault runs as more
 * than one instance; in memory is correct for one.
 */
export interface ReplayCache {
  /**
   * Records `jti` as used until `expiresAtMs`. "fresh": first use, proceed.
   * "replayed": seen before, refuse. "full": no room without dropping a live
   * id, refuse — failing closed beats forgetting what was used.
   */
  record(jti: string, expiresAtMs: number, nowMs: number): "fresh" | "replayed" | "full";
}

export function createInMemoryReplayCache(options?: { readonly maxEntries?: number }): ReplayCache {
  // Only proofs with a valid signature from a registered agent reach the
  // cache, and each lives about two skew windows, so this bound is generous.
  const maxEntries = options?.maxEntries ?? 100_000;
  const expiries = new Map<string, number>();

  function pruneExpired(nowMs: number): void {
    for (const [jti, expiresAtMs] of expiries) {
      if (expiresAtMs < nowMs) expiries.delete(jti);
    }
  }

  return {
    record(jti, expiresAtMs, nowMs) {
      const existing = expiries.get(jti);
      if (existing !== undefined && existing >= nowMs) return "replayed";
      if (expiries.size >= maxEntries) {
        pruneExpired(nowMs);
        if (expiries.size >= maxEntries) return "full";
      }
      expiries.set(jti, expiresAtMs);
      return "fresh";
    },
  };
}

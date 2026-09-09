export interface BroadcastOutcome {
  readonly delivered: number;
  readonly failed: readonly string[];
}

/**
 * Pushes a signed tombstone to every registered subscriber (CLAUDE.md
 * section 3, "push, don't pull": the control plane pushes revocation state
 * into local caches on change, so the hot path never blocks on it).
 *
 * An interface rather than a bare function so a multi-instance deployment
 * can swap in Redis pub/sub without touching callers — the same shape as
 * `KeyProvider` and `SecretCipher`. HTTP fan-out is what Phase 3 needs; a
 * broker is a scale concern, and CLAUDE.md section 2 says implementations
 * wait for demand.
 */
export interface TombstoneBroadcaster {
  broadcast(tombstone: string): Promise<BroadcastOutcome>;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Delivers to every subscriber concurrently and never lets one unreachable
 * subscriber block the others: a revocation that reaches two of three tools
 * is strictly better than one that reaches none. Failures are reported back
 * so the caller can surface them; subscribers that miss a push converge on
 * their next resync against `GET /revocations`.
 */
export function createHttpBroadcaster(params: {
  readonly subscriberUrls: readonly string[];
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}): TombstoneBroadcaster {
  const { subscriberUrls, fetchImpl = fetch, timeoutMs = 2_000 } = params;

  return {
    async broadcast(tombstone: string): Promise<BroadcastOutcome> {
      const results = await Promise.all(
        subscriberUrls.map(async (baseUrl) => {
          const url = `${baseUrl.replace(/\/$/, "")}/revocations`;
          try {
            const response = await fetchImpl(url, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ tombstone }),
              signal: AbortSignal.timeout(timeoutMs),
            });
            return response.ok ? null : `${url}: HTTP ${response.status}`;
          } catch (error) {
            return `${url}: ${errorMessage(error)}`;
          }
        }),
      );

      const failed = results.filter((failure): failure is string => failure !== null);
      return { delivered: subscriberUrls.length - failed.length, failed };
    },
  };
}

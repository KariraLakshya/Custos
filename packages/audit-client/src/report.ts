import type { AuditEvent } from "@custos/contracts";

export type { AuditEvent };

/**
 * Reports one action outcome to the audit service. Shared by every service
 * that reports: the vault (agent actions and its control-plane writes),
 * identity and revocation (their control-plane writes). `report` returns `void`,
 * not a `Promise` — deliberately, so nothing can accidentally `await` it and
 * put an audit write on the hot path (CLAUDE.md section 3: "audit writes are
 * asynchronous and non-blocking; no request waits on an audit write").
 *
 * Interface-shaped like `TombstoneBroadcaster`/`KeyProvider` for the same
 * reason: HTTP push today, a queue later, without touching callers.
 */
export interface AuditReporter {
  report(event: AuditEvent): void;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Fires the report and does not wait for it. A failed or slow audit service
 * must never affect the caller's own response — audit loss is a bug, but
 * audit-induced latency is also a bug (CLAUDE.md section 3). Failures are
 * only ever reported through `onError` (logging), never thrown.
 */
export function createHttpAuditReporter(params: {
  readonly auditUrl: string;
  /**
   * This service's own key, with `audit:write` (ADR 0008). Never logged.
   * Omitted when the service proves itself with a client certificate
   * instead, through an mTLS `fetchImpl` (ADR 0009).
   */
  readonly serviceKey?: string;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
  readonly onError?: (error: unknown) => void;
}): AuditReporter {
  const { auditUrl, serviceKey, fetchImpl = fetch, timeoutMs = 2_000, onError } = params;
  const recordsUrl = `${auditUrl.replace(/\/$/, "")}/records`;

  return {
    report(event) {
      void (async () => {
        try {
          const response = await fetchImpl(recordsUrl, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              ...(serviceKey === undefined ? {} : { authorization: `Bearer ${serviceKey}` }),
            },
            body: JSON.stringify(event),
            signal: AbortSignal.timeout(timeoutMs),
          });
          if (!response.ok) {
            onError?.(new Error(`audit service responded HTTP ${response.status}`));
          }
        } catch (error) {
          onError?.(new Error(errorMessage(error)));
        }
      })();
    },
  };
}

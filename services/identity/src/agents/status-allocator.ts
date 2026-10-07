import { err, ok, type Result } from "@custos/core";

export interface AllocatedStatus {
  readonly statusListIndex: number;
  readonly statusListCredential: string;
}

export type AllocateStatusError = {
  readonly code: "STATUS_ALLOCATION_FAILED";
  readonly reason: string;
};

/**
 * Reserves this agent's bit in the revocation service's published status
 * list. Injected rather than called directly so tests can register agents
 * without standing up the revocation service.
 */
export interface StatusAllocator {
  allocate(params: {
    readonly agentId: string;
    readonly agentDid: string;
  }): Promise<Result<AllocatedStatus, AllocateStatusError>>;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isAllocatedStatus(value: unknown): value is AllocatedStatus {
  if (typeof value !== "object" || value === null) return false;
  const body = value as Record<string, unknown>;
  return (
    typeof body.statusListIndex === "number" &&
    Number.isInteger(body.statusListIndex) &&
    body.statusListIndex >= 0 &&
    typeof body.statusListCredential === "string" &&
    body.statusListCredential.length > 0
  );
}

/**
 * Allocation is deliberately a hard dependency of registration: if the
 * revocation service is unreachable we refuse to issue the credential rather
 * than issue one with no status entry. An agent that cannot be revoked is
 * the one failure mode this product exists to prevent, so registration fails
 * closed (CLAUDE.md section 4).
 */
export function createHttpStatusAllocator(params: {
  readonly revocationUrl: string;
  /** This service's own key, with `status:allocate` (ADR 0008). Never logged. */
  /** Omitted when identity calls through Envoy with its certificate (ADR 0009). */
  readonly serviceKey?: string;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}): StatusAllocator {
  const { revocationUrl, serviceKey, fetchImpl = fetch, timeoutMs = 2_000 } = params;

  return {
    async allocate({ agentId, agentDid }) {
      const url = `${revocationUrl.replace(/\/$/, "")}/agents`;
      try {
        const response = await fetchImpl(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(serviceKey === undefined ? {} : { authorization: `Bearer ${serviceKey}` }),
          },
          body: JSON.stringify({ agentId, agentDid }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) {
          return err({
            code: "STATUS_ALLOCATION_FAILED",
            reason: `${url}: HTTP ${response.status}`,
          });
        }
        const body: unknown = await response.json();
        if (!isAllocatedStatus(body)) {
          return err({
            code: "STATUS_ALLOCATION_FAILED",
            reason: `${url}: response missing statusListIndex/statusListCredential`,
          });
        }
        return ok({
          statusListIndex: body.statusListIndex,
          statusListCredential: body.statusListCredential,
        });
      } catch (error) {
        return err({ code: "STATUS_ALLOCATION_FAILED", reason: `${url}: ${errorMessage(error)}` });
      }
    },
  };
}

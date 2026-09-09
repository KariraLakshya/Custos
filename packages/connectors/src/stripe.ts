import { err, ok } from "@custos/contracts";
import { createRevocationGuard, type Connector } from "./connector.js";

const DEFAULT_BASE_URL = "https://api.stripe.com/v1";

function isListCustomersInput(value: unknown): value is { limit?: number } | undefined {
  if (value === undefined) return true;
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return v.limit === undefined || typeof v.limit === "number";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Real Stripe test-mode connector: plain `fetch` against Stripe's REST API,
 * no `stripe` SDK dependency (CLAUDE.md section 4 — prefer a primitive over
 * a convenience wrapper). `credential` is the caller-decrypted secret key
 * (`sk_test_...`); this connector never stores it.
 */
export function createStripeConnector(options?: { readonly baseUrl?: string }): Connector {
  const baseUrl = options?.baseUrl ?? DEFAULT_BASE_URL;
  const guard = createRevocationGuard();

  return {
    tool: "stripe",
    async call({ action, input, credential, agentId }) {
      if (guard.isRevoked(agentId)) {
        return err({ code: "AGENT_REVOKED", agentId });
      }
      if (action !== "list-customers") {
        return err({ code: "UNKNOWN_ACTION", action });
      }
      if (!isListCustomersInput(input)) {
        return err({ code: "INVALID_INPUT", reason: "expected { limit?: number } or no input" });
      }
      const limit = input?.limit;
      const url = new URL("/customers", baseUrl);
      if (limit !== undefined) url.searchParams.set("limit", String(limit));

      let response: Response;
      try {
        response = await fetch(url, {
          headers: { Authorization: `Bearer ${credential}` },
        });
      } catch (error) {
        return err({ code: "UPSTREAM_ERROR", reason: errorMessage(error) });
      }
      if (!response.ok) {
        return err({
          code: "UPSTREAM_ERROR",
          status: response.status,
          reason: await response.text(),
        });
      }
      return ok(await response.json());
    },
    async revoke(agentId) {
      // Stripe has no per-agent concept while the vault holds one account
      // key, so this refuses the agent locally rather than calling Stripe.
      // Once agents each hold a restricted key, this is also where that key
      // gets deleted upstream — the enforcement point stays the same.
      guard.revoke(agentId);
    },
  };
}

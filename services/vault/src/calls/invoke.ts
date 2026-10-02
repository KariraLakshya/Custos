import { verifyScopedToken, type SecretCipher } from "@custos/core";
import { err, type Result } from "@custos/contracts";
import type { Connector, ConnectorCallError } from "@custos/connectors";
import { loadToolCredential } from "../credentials/store.js";
import type { AuditReporter } from "@custos/audit-client";
import type { VaultDb } from "../db/client.js";

export type InvokeToolError =
  | { readonly code: "INVALID_TOKEN"; readonly reason: string }
  | { readonly code: "ACTION_MISMATCH" }
  | { readonly code: "AGENT_REVOKED"; readonly agentId: string }
  | { readonly code: "REVOCATION_STATE_STALE"; readonly reason: string }
  | { readonly code: "UNKNOWN_TOOL"; readonly tool: string }
  | ConnectorCallError;

/** The hot path's local revocation view — no database, no network. */
export interface RevocationGate {
  isRevoked(agentDid: string): boolean;
  isStale(now: Date): boolean;
}

/**
 * Redeems a scoped token for one tool call. Token verification and the
 * revocation check are both entirely local (CLAUDE.md section 3, hot path) —
 * no DB or network access happens until after both have already checked out.
 * The decrypted credential lives only in this function's stack for the
 * duration of the call and is never logged (CLAUDE.md section 4).
 *
 * Revocation is checked on every call rather than only at token issuance:
 * a token is valid for 60 seconds, and the whole point of Phase 3 is that a
 * revoked agent stops working in about one second, not up to sixty.
 */
export async function invokeTool(params: {
  readonly db: VaultDb;
  readonly cipher: SecretCipher;
  readonly connectors: ReadonlyMap<string, Connector>;
  readonly token: string;
  readonly vaultPublicKey: Uint8Array;
  readonly action: string;
  readonly input: unknown;
  readonly now: Date;
  readonly revocation: RevocationGate;
  /**
   * Reports every outcome once the caller's identity is known (i.e. after
   * the token itself has verified) — an unauthenticated attempt is not
   * attributable to an agent, so `INVALID_TOKEN` is the one outcome that is
   * never audited. Optional so existing callers/tests are unaffected.
   */
  readonly auditReporter?: AuditReporter;
}): Promise<Result<unknown, InvokeToolError>> {
  const {
    db,
    cipher,
    connectors,
    token,
    vaultPublicKey,
    action,
    input,
    now,
    revocation,
    auditReporter,
  } = params;

  const verified = verifyScopedToken({ token, publicKey: vaultPublicKey, now });
  if (!verified.ok) {
    return err({ code: "INVALID_TOKEN", reason: verified.error.code });
  }
  const claims = verified.value;

  function report(
    decision: "allow" | "deny",
    rule: string,
    reason?: string,
    categories?: readonly string[],
  ) {
    auditReporter?.report({
      agentDid: claims.sub,
      tool: claims.tool,
      action,
      dataCategories: categories ?? [],
      policy: { rule, decision },
      ...(reason === undefined ? {} : { reason }),
    });
  }

  if (claims.action !== action) {
    report("deny", "token-scope", `token is scoped to action "${claims.action}"`);
    return err({ code: "ACTION_MISMATCH" });
  }

  if (revocation.isRevoked(claims.sub)) {
    report("deny", "revocation", "agent is revoked");
    return err({ code: "AGENT_REVOKED", agentId: claims.sub });
  }
  // Fail closed on bounded staleness: if the local view is too old to trust,
  // deny rather than serve an allow decision from a stale cache.
  if (revocation.isStale(now)) {
    report(
      "deny",
      "revocation-state-stale",
      "local revocation state is older than the configured bound",
    );
    return err({
      code: "REVOCATION_STATE_STALE",
      reason: "local revocation state is older than the configured bound",
    });
  }

  const connector = connectors.get(claims.tool);
  if (!connector) {
    report("deny", "unknown-tool", "no connector registered for this tool");
    return err({ code: "UNKNOWN_TOOL", tool: claims.tool });
  }

  const credential = await loadToolCredential({ db, cipher, tool: claims.tool });
  if (credential === null) {
    report("deny", "unknown-tool", "no stored credential for this tool", connector.dataCategories);
    return err({ code: "UNKNOWN_TOOL", tool: claims.tool });
  }

  const result = await connector.call({ action, input, credential, agentId: claims.sub });
  if (result.ok) {
    report("allow", "scoped-token", undefined, connector.dataCategories);
  } else {
    report("deny", "connector", result.error.code, connector.dataCategories);
  }
  return result;
}

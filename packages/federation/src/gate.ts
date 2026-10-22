import type { AuditEvent } from "@custos/contracts";
import { ErrorCode } from "@custos/contracts";
import type { AuditReporter } from "@custos/audit-client";
import {
  assertNever,
  err,
  ok,
  verifyForeignAgent,
  type ForeignAgent,
  type ForeignDenial,
  type ForeignReplayGuard,
  type Result,
  type TrustAnchor,
  type VerifiedForeignIdentity,
  type VerifiedForeignStatusList,
} from "@custos/core";
import type { ConfiguredAnchor } from "./anchors.js";

/** What the caller is told. Deliberately coarse: it never says which check failed. */
export interface PublicDenial {
  readonly status: 401 | 403 | 503;
  readonly code:
    typeof ErrorCode.UNAUTHORIZED | typeof ErrorCode.AGENT_REVOKED | typeof ErrorCode.UNAVAILABLE;
}

/**
 * A refusal. `status` and `code` go in the response; `denial` is the precise
 * reason and goes to the log only.
 */
export interface GateDenial extends PublicDenial {
  readonly denial: ForeignDenial | { readonly code: "GATE_FAILURE"; readonly reason: string };
}

const UNAUTHORIZED: PublicDenial = { status: 401, code: ErrorCode.UNAUTHORIZED };
const UNAVAILABLE: PublicDenial = { status: 503, code: ErrorCode.UNAVAILABLE };

/**
 * Credential, proof, anchor and replay failures all answer the same 401 so a
 * caller cannot probe which organisations B trusts or which check it failed.
 * A credential without a usable status entry is a defect in the credential and
 * retrying cannot fix it, so it is a 401 too. A revoked agent is told so (403): it is a fact about the agent, not about B's
 * configuration. A missing, stale or mismatched status list, or a full replay
 * guard, is B's own condition and is retryable (503); it still refuses.
 *
 * An exhaustive switch: a new core denial fails typecheck here rather than
 * falling through to some default.
 */
export function toPublicDenial(denial: ForeignDenial): PublicDenial {
  switch (denial.code) {
    case "MALFORMED_INPUT":
    case "NO_TRUST_ANCHOR":
    case "ANCHOR_DISABLED":
    case "ANCHOR_INVALID":
    case "CREDENTIAL_SIGNATURE_INVALID":
    case "CREDENTIAL_SUBJECT_INVALID":
    case "CREDENTIAL_TIME_INVALID":
    case "CREDENTIAL_NOT_YET_VALID":
    case "CREDENTIAL_EXPIRED":
    case "PROOF_REJECTED":
    case "PROOF_REPLAYED":
    case "STATUS_ENTRY_INVALID":
      return UNAUTHORIZED;
    case "AGENT_REVOKED":
      return { status: 403, code: ErrorCode.AGENT_REVOKED };
    case "REPLAY_GUARD_FULL":
    case "STATUS_UNAVAILABLE":
    case "STATUS_VIEW_MISMATCH":
    case "STATUS_STALE":
      return UNAVAILABLE;
    default:
      return assertNever(denial);
  }
}

/**
 * The identity a denial may be audited under, or `undefined` to only log it.
 * Audited: denials made after the credential's signature and the caller's
 * proof of possession both verified and the proof was not a replay, so the
 * agent is genuinely the one named. Everything earlier is logged and never
 * audited, so nobody can fill the evidence log with unauthenticated noise
 * (ADR 0008: authentication failures are logged, not audited).
 */
function auditedIdentity(denial: ForeignDenial): VerifiedForeignIdentity | undefined {
  switch (denial.code) {
    case "AGENT_REVOKED":
    case "STATUS_ENTRY_INVALID":
    case "STATUS_UNAVAILABLE":
    case "STATUS_VIEW_MISMATCH":
    case "STATUS_STALE":
      return denial;
    case "MALFORMED_INPUT":
    case "NO_TRUST_ANCHOR":
    case "ANCHOR_DISABLED":
    case "ANCHOR_INVALID":
    case "CREDENTIAL_SIGNATURE_INVALID":
    case "CREDENTIAL_SUBJECT_INVALID":
    case "CREDENTIAL_TIME_INVALID":
    case "CREDENTIAL_NOT_YET_VALID":
    case "CREDENTIAL_EXPIRED":
    case "PROOF_REJECTED":
    case "PROOF_REPLAYED":
    case "REPLAY_GUARD_FULL":
      return undefined;
    default:
      return assertNever(denial);
  }
}

export interface ForeignCall {
  /** From the caller; untrusted until checked. */
  readonly credential: unknown;
  readonly proof: unknown;
  /** What the caller is attempting, for the audit record. Defaults to `foreign.call`. */
  readonly tool?: string;
  readonly action?: string;
}

export interface ForeignAgentGate {
  check(call: ForeignCall): Promise<Result<ForeignAgent, GateDenial>>;
}

const DEFAULT_ACTION = "foreign.call";

/**
 * B's decision on a call from an agent another organisation issued (ADR 0014):
 * `verifyForeignAgent` against the pinned anchors and the cached status view,
 * with the response coarsened and the outcome audited. The hot path: it makes
 * no network call, and the audit write is fire-and-forget.
 *
 * Fails closed: if anything in the decision throws (a shared replay store
 * going down, say) the caller is refused with a 503, never let through and
 * never given a stack trace.
 */
export function createForeignAgentGate(params: {
  readonly anchors: readonly ConfiguredAnchor[];
  readonly statusViewFor: (anchor: TrustAnchor) => VerifiedForeignStatusList | undefined;
  /** This receiver's identifier: proofs must be addressed to it. */
  readonly audience: string;
  readonly replay: ForeignReplayGuard;
  readonly now: () => Date;
  /** Explicit configuration, no default. */
  readonly maxProofSkewSeconds: number;
  /** Explicit configuration, no default. */
  readonly maxClockSkewSeconds: number;
  readonly audit?: AuditReporter;
  /** Every refusal, with its precise reason, for the embedder's log. */
  readonly onDenied?: (denial: GateDenial["denial"]) => void;
}): ForeignAgentGate {
  const { audit, onDenied } = params;

  function report(event: AuditEvent): void {
    try {
      audit?.report(event);
    } catch {
      // Audit must never decide the response (CLAUDE.md section 3).
    }
  }

  function logDenied(denial: GateDenial["denial"]): void {
    try {
      onDenied?.(denial);
    } catch {
      // Logging must never decide the response.
    }
  }

  return {
    async check(call) {
      const action = call.action ?? DEFAULT_ACTION;
      const tool = call.tool === undefined ? {} : { tool: call.tool };

      let verdict: Result<ForeignAgent, ForeignDenial>;
      try {
        verdict = await verifyForeignAgent({
          credential: call.credential,
          proof: call.proof,
          anchors: params.anchors,
          statusViewFor: params.statusViewFor,
          audience: params.audience,
          replay: params.replay,
          now: params.now(),
          maxProofSkewSeconds: params.maxProofSkewSeconds,
          maxClockSkewSeconds: params.maxClockSkewSeconds,
        });
      } catch (error) {
        const denial = {
          code: "GATE_FAILURE" as const,
          reason: error instanceof Error ? error.message : "verification threw",
        };
        logDenied(denial);
        return err({ ...UNAVAILABLE, denial });
      }

      if (verdict.ok) {
        const agent = verdict.value;
        report({
          agentDid: agent.agentDid,
          ...tool,
          action,
          dataCategories: [],
          policy: { rule: `foreign:${agent.domain}`, decision: "allow" },
          reason: `issuer=${agent.issuerDid} status-as-of=${agent.statusAsOf.toISOString()}`,
        });
        return ok(agent);
      }

      const denial = verdict.error;
      logDenied(denial);
      const who = auditedIdentity(denial);
      if (who !== undefined) {
        const detail = denial.code === "STATUS_ENTRY_INVALID" ? ` ${denial.reason}` : "";
        report({
          agentDid: who.agentDid,
          ...tool,
          action,
          dataCategories: [],
          policy: { rule: `foreign:${who.domain}`, decision: "deny" },
          reason: `issuer=${who.issuerDid} code=${denial.code}${detail}`,
        });
      }
      return err({ ...toPublicDenial(denial), denial });
    },
  };
}

import {
  handOffHash,
  issueScopedToken,
  multibaseToPublicKey,
  proofReplayExpiresAtMs,
  verifyCredential,
  verifyDelegationChain,
  verifyTokenRequestProof,
  type DelegationChainError,
  type DelegationLimits,
  type KeyProvider,
  type SignedCredential,
} from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { toolCredentialExists } from "../credentials/store.js";
import { isToolAllowed, rootGrantOf, type GrantedBy } from "../policy/policy.js";
import type { VaultDb } from "../db/client.js";
import type { ReplayCache } from "./replay-cache.js";
import type { TrustedIssuer } from "./trusted-issuer.js";

const DEFAULT_TTL_SECONDS = 60;

export type IssueToolTokenError =
  | { readonly code: "UNKNOWN_TOOL"; readonly tool: string }
  | { readonly code: "INVALID_AGENT_CREDENTIAL"; readonly reason: string }
  | { readonly code: "INVALID_PROOF_OF_POSSESSION"; readonly reason: string }
  /** `revokedDid` is set when the revoked agent is a delegator, not the requester. */
  | { readonly code: "AGENT_REVOKED"; readonly agentId: string; readonly revokedDid?: string }
  | { readonly code: "POLICY_DENIED"; readonly agentId: string; readonly tool: string }
  /**
   * A presented delegation chain was refused (ADR 0020). `agentId` is the
   * requester, already proven; nothing the refused chain claims is reported.
   */
  | {
      readonly code: "DELEGATION_DENIED";
      readonly agentId: string;
      readonly reason:
        | DelegationChainError["code"]
        | "DELEGATOR_STATUS_INVALID"
        | "NO_ROOT_GRANT"
        | "CHAIN_ENDS_NOW";
    }
  | { readonly code: "SIGNING_FAILED"; readonly reason: string };

export interface IssuedToolToken {
  readonly token: string;
  readonly expiresAt: string;
}

/** What a delegated token was issued under: the evidence the audit record carries. */
export interface IssuedDelegation {
  readonly agentId: string;
  /** From the first delegator to the requester. */
  readonly chain: readonly string[];
  /** The operator whose grant to the first delegator is the root (ADR 0020 §1). */
  readonly root: GrantedBy;
  readonly handOffs: readonly string[];
  readonly credentials: readonly unknown[];
  /** `handOffHash` of the hand-off naming the requester; the token's `dref`. */
  readonly ref: string;
  /** The vault's time of the check, which an auditor re-verifies the chain at. */
  readonly checkedAt: string;
}

/**
 * The agent's identity is the credential's subject, not its issuer (ADR 0007
 * decision 2: the issuer is the identity service, the same for every agent).
 * Read only after the credential has verified — before that, it is a claim.
 */
function subjectOf(credential: SignedCredential): string | null {
  const subject = credential.credentialSubject as { id?: unknown } | undefined;
  return typeof subject?.id === "string" && subject.id.length > 0 ? subject.id : null;
}

/** The agent's own public key, embedded by the issuer (ADR 0007 decision 2). Read only after verification. */
function agentKeyOf(credential: SignedCredential): Uint8Array | null {
  const subject = credential.credentialSubject as { publicKeyMultibase?: unknown } | undefined;
  if (typeof subject?.publicKeyMultibase !== "string") return null;
  const key = multibaseToPublicKey(subject.publicKeyMultibase);
  return key.ok ? key.value : null;
}

/** How to check the proof that the caller holds the agent's private key (ADR 0007 decision 3). */
export interface ProofCheck {
  readonly proof: string;
  /** The vault's own public `/tokens` URL: the only audience a proof may name. */
  readonly audience: string;
  readonly maxSkewSeconds: number;
  readonly replayCache: ReplayCache;
}

/**
 * Issues a 60s-default scoped token (CLAUDE.md section 4) for a verified
 * agent, bound to one tool and one action. Requires: the credential was
 * issued by the pinned trusted issuer and verifies against its published key,
 * the tool has a stored credential, the agent is not revoked, and it holds a
 * grant for the tool — in that order, so nothing is decided about an
 * identity before that identity is cryptographically confirmed.
 */
export async function issueToolToken(params: {
  readonly db: VaultDb;
  readonly keyProvider: KeyProvider;
  readonly signingKeyId: string;
  readonly agentCredential: SignedCredential;
  readonly tool: string;
  readonly action: string;
  readonly now: Date;
  readonly ttlSeconds?: number;
  readonly revocation: {
    trackAgent(
      agentDid: string,
      credentialStatus: unknown,
      now: Date,
    ): Result<undefined, { readonly reason: string }>;
    verdict(agentDid: string): "ok" | "revoked" | "unknown";
  };
  readonly trustedIssuer: TrustedIssuer;
  readonly proofOfPossession: ProofCheck;
  /**
   * A chain the requester acts under (ADR 0020), with the limits it is held
   * to. Absent: the requester acts on its own grant, as before.
   */
  readonly delegation?: { readonly chain: unknown; readonly limits: DelegationLimits };
}): Promise<
  Result<IssuedToolToken & { readonly delegation?: IssuedDelegation }, IssueToolTokenError>
> {
  const {
    db,
    keyProvider,
    signingKeyId,
    agentCredential,
    tool,
    action,
    now,
    revocation,
    trustedIssuer,
    proofOfPossession,
    ttlSeconds = DEFAULT_TTL_SECONDS,
  } = params;

  // A credential from any issuer but the pinned one is refused outright —
  // including a self-issued one, which anyone with a keypair can produce.
  if (agentCredential.issuer !== trustedIssuer.did) {
    return err({ code: "INVALID_AGENT_CREDENTIAL", reason: "UNTRUSTED_ISSUER" });
  }

  if (!(await toolCredentialExists(db, tool))) {
    return err({ code: "UNKNOWN_TOOL", tool });
  }

  const issuerDocument = await trustedIssuer.resolveDidDocument();
  if (!issuerDocument.ok) {
    return err({ code: "INVALID_AGENT_CREDENTIAL", reason: issuerDocument.error });
  }

  const verified = await verifyCredential({
    credential: agentCredential,
    didDocument: issuerDocument.value,
  });
  if (!verified.ok) {
    return err({ code: "INVALID_AGENT_CREDENTIAL", reason: verified.error.code });
  }

  const agentId = subjectOf(agentCredential);
  if (agentId === null) {
    return err({ code: "INVALID_AGENT_CREDENTIAL", reason: "MISSING_SUBJECT" });
  }
  const agentKey = agentKeyOf(agentCredential);
  if (agentKey === null) {
    return err({ code: "INVALID_AGENT_CREDENTIAL", reason: "MISSING_AGENT_KEY" });
  }

  // The credential is genuine; now the caller must prove it holds the key
  // named in it. A copied credential stops here, before any decision is made
  // or recorded about the agent it names.
  // The proof must also have been made for this very tool and action
  // (ADR 0015), so a captured request cannot be spent on another granted
  // tool. Checked before the replay cache, so a mismatch uses nothing up.
  const proof = verifyTokenRequestProof({
    proof: proofOfPossession.proof,
    publicKey: agentKey,
    expectedAudience: proofOfPossession.audience,
    expectedRequest: { tool, action },
    now,
    maxSkewSeconds: proofOfPossession.maxSkewSeconds,
  });
  if (!proof.ok) {
    return err({ code: "INVALID_PROOF_OF_POSSESSION", reason: proof.error.code });
  }

  // The chain, if any, is checked now: after the proof has shown who the
  // requester is, and before the proof's id is recorded, so a refused chain
  // does not use the proof up (ADR 0015 order). Pure and local: the issuer's
  // document was resolved above, and nothing here calls out (ADR 0020 §3).
  const chain =
    params.delegation === undefined
      ? undefined
      : await verifyDelegationChain({
          chain: params.delegation.chain,
          requesterDid: agentId,
          request: { tool, action },
          issuer: { did: trustedIssuer.did, document: issuerDocument.value },
          now,
          limits: params.delegation.limits,
        });
  if (chain !== undefined && !chain.ok) {
    return err({ code: "DELEGATION_DENIED", agentId, reason: chain.error.code });
  }

  // Recorded only once the signature is valid, so nobody but the agent can
  // spend its proof ids. Kept until the proof would be stale anyway.
  const replay = proofOfPossession.replayCache.record(
    `${agentId} ${proof.value.jti}`,
    proofReplayExpiresAtMs(proof.value.iat, proofOfPossession.maxSkewSeconds),
    now.getTime(),
  );
  if (replay !== "fresh") {
    return err({
      code: "INVALID_PROOF_OF_POSSESSION",
      reason: replay === "replayed" ? "REPLAYED" : "REPLAY_CACHE_FULL",
    });
  }

  // Revocation and authorization are decided only now that the agent's
  // identity is cryptographically confirmed — a decision about an unverified
  // claimant means nothing, and would put its claimed name in the audit log.
  // A revoked agent gets no new tokens: revocation closes the issuance path
  // as well as the call path.
  // The credential names the status list bit that is this agent's. It is read
  // only now that the credential is verified and the caller has proved it holds
  // the agent's key, and it is what lets the hot path look the agent up later.
  const tracked = revocation.trackAgent(agentId, agentCredential.credentialStatus, now);
  if (!tracked.ok) {
    return err({ code: "INVALID_AGENT_CREDENTIAL", reason: tracked.error.reason });
  }
  if (revocation.verdict(agentId) !== "ok") {
    return err({ code: "AGENT_REVOKED", agentId });
  }

  const iat = Math.floor(now.getTime() / 1000);
  let exp = iat + ttlSeconds;
  let delegation: IssuedDelegation | undefined;

  if (chain === undefined) {
    // Build plan Phase 4: "simple allowlists per agent × tool". Fail closed:
    // no grant row means denied.
    if (!(await isToolAllowed(db, agentId, tool))) {
      return err({ code: "POLICY_DENIED", agentId, tool });
    }
  } else {
    // Every delegator becomes known to the revocation view from its own
    // signed credential, so one that never asked for a token itself is "ok"
    // or "revoked", never "unknown" (ADR 0020 §4).
    for (const delegator of chain.value.delegators) {
      if (!revocation.trackAgent(delegator.did, delegator.credentialStatus, now).ok) {
        return err({ code: "DELEGATION_DENIED", agentId, reason: "DELEGATOR_STATUS_INVALID" });
      }
    }
    for (const did of chain.value.dids) {
      if (revocation.verdict(did) !== "ok") {
        return err({ code: "AGENT_REVOKED", agentId, revokedDid: did });
      }
    }
    // The root: an operator's grant of this tool to the first delegator.
    // The requester needs no grant of its own.
    const root = await rootGrantOf(db, chain.value.rootDid, tool);
    if (root === null) {
      return err({ code: "DELEGATION_DENIED", agentId, reason: "NO_ROOT_GRANT" });
    }
    // The token never outlives a hand-off or a delegator's credential.
    exp = Math.min(exp, Math.floor(chain.value.expiresAt.getTime() / 1000));
    if (exp <= iat) {
      return err({ code: "DELEGATION_DENIED", agentId, reason: "CHAIN_ENDS_NOW" });
    }
    const presented = params.delegation!.chain as {
      handOffs: readonly string[];
      credentials: readonly unknown[];
    };
    delegation = {
      agentId,
      chain: chain.value.dids,
      root,
      handOffs: presented.handOffs,
      credentials: presented.credentials,
      // The chain verified, so it has at least one hand-off.
      ref: handOffHash(presented.handOffs[presented.handOffs.length - 1]!),
      checkedAt: now.toISOString(),
    };
  }

  const issued = await issueScopedToken({
    claims: {
      sub: agentId,
      tool,
      action,
      iat,
      exp,
      ...(delegation === undefined ? {} : { chain: delegation.chain, dref: delegation.ref }),
    },
    signer: { sign: (data) => keyProvider.sign(signingKeyId, data) },
  });
  if (!issued.ok) {
    return err({ code: "SIGNING_FAILED", reason: issued.error.reason });
  }

  return ok({
    token: issued.value,
    expiresAt: new Date(exp * 1000).toISOString(),
    ...(delegation === undefined ? {} : { delegation }),
  });
}

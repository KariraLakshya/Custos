import {
  issueScopedToken,
  verifyCredential,
  type KeyProvider,
  type SignedCredential,
} from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { toolCredentialExists } from "../credentials/store.js";
import { isToolAllowed } from "../policy/policy.js";
import type { VaultDb } from "../db/client.js";
import type { TrustedIssuer } from "./trusted-issuer.js";

const DEFAULT_TTL_SECONDS = 60;

export type IssueToolTokenError =
  | { readonly code: "UNKNOWN_TOOL"; readonly tool: string }
  | { readonly code: "INVALID_AGENT_CREDENTIAL"; readonly reason: string }
  | { readonly code: "AGENT_REVOKED"; readonly agentId: string }
  | { readonly code: "POLICY_DENIED"; readonly agentId: string; readonly tool: string }
  | { readonly code: "SIGNING_FAILED"; readonly reason: string };

export interface IssuedToolToken {
  readonly token: string;
  readonly expiresAt: string;
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
  readonly revocation: { isRevoked(agentDid: string): boolean };
  readonly trustedIssuer: TrustedIssuer;
}): Promise<Result<IssuedToolToken, IssueToolTokenError>> {
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

  // Revocation and authorization are decided only now that the agent's
  // identity is cryptographically confirmed — a decision about an unverified
  // claimant means nothing, and would put its claimed name in the audit log.
  // A revoked agent gets no new tokens: revocation closes the issuance path
  // as well as the call path.
  if (revocation.isRevoked(agentId)) {
    return err({ code: "AGENT_REVOKED", agentId });
  }

  // Build plan Phase 4: "simple allowlists per agent × tool". Fail closed:
  // no grant row means denied.
  if (!(await isToolAllowed(db, agentId, tool))) {
    return err({ code: "POLICY_DENIED", agentId, tool });
  }

  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + ttlSeconds;
  const issued = await issueScopedToken({
    claims: { sub: agentId, tool, action, iat, exp },
    signer: { sign: (data) => keyProvider.sign(signingKeyId, data) },
  });
  if (!issued.ok) {
    return err({ code: "SIGNING_FAILED", reason: issued.error.reason });
  }

  return ok({ token: issued.value, expiresAt: new Date(exp * 1000).toISOString() });
}

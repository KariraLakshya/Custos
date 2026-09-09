import {
  didWebToResolutionUrl,
  issueScopedToken,
  verifyCredential,
  type DidWebDocument,
  type KeyProvider,
  type SignedCredential,
} from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { toolCredentialExists } from "../credentials/store.js";
import type { VaultDb } from "../db/client.js";

const DEFAULT_TTL_SECONDS = 60;

export type IssueToolTokenError =
  | { readonly code: "UNKNOWN_TOOL"; readonly tool: string }
  | { readonly code: "INVALID_AGENT_CREDENTIAL"; readonly reason: string }
  | { readonly code: "AGENT_REVOKED"; readonly agentId: string }
  | { readonly code: "SIGNING_FAILED"; readonly reason: string };

export interface IssuedToolToken {
  readonly token: string;
  readonly expiresAt: string;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Resolves and returns the issuer's DID document fresh over HTTP — the same
 * independent-verification pattern as `apps/cli`'s `verify` command (see
 * CLAUDE.md section 3): the vault shares no state with whatever issued this
 * credential. This is the cold path (token issuance, not the per-call hot
 * path), so a network call here is fine.
 */
async function resolveAgentDidDocument(issuer: string): Promise<Result<DidWebDocument, string>> {
  const resolutionUrl = didWebToResolutionUrl(issuer);
  let response: Response;
  try {
    response = await fetch(resolutionUrl);
  } catch (error) {
    return err(`could not reach issuer DID document (${resolutionUrl}): ${errorMessage(error)}`);
  }
  if (!response.ok) {
    return err(`could not resolve issuer DID document (${resolutionUrl}): HTTP ${response.status}`);
  }
  return ok((await response.json()) as DidWebDocument);
}

/**
 * Issues a 60s-default scoped token (CLAUDE.md section 4) for a verified
 * agent, bound to one tool and one action. Requires: the tool has a stored
 * credential, and the agent's identity credential independently verifies.
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
    ttlSeconds = DEFAULT_TTL_SECONDS,
  } = params;

  // Checked before anything expensive: a revoked agent gets no new tokens,
  // so revocation closes the issuance path as well as the call path.
  if (revocation.isRevoked(agentCredential.issuer)) {
    return err({ code: "AGENT_REVOKED", agentId: agentCredential.issuer });
  }

  if (!(await toolCredentialExists(db, tool))) {
    return err({ code: "UNKNOWN_TOOL", tool });
  }

  const didDocument = await resolveAgentDidDocument(agentCredential.issuer);
  if (!didDocument.ok) {
    return err({ code: "INVALID_AGENT_CREDENTIAL", reason: didDocument.error });
  }

  const verified = await verifyCredential({
    credential: agentCredential,
    didDocument: didDocument.value,
  });
  if (!verified.ok) {
    return err({ code: "INVALID_AGENT_CREDENTIAL", reason: verified.error.code });
  }

  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + ttlSeconds;
  const issued = await issueScopedToken({
    claims: { sub: agentCredential.issuer, tool, action, iat, exp },
    signer: { sign: (data) => keyProvider.sign(signingKeyId, data) },
  });
  if (!issued.ok) {
    return err({ code: "SIGNING_FAILED", reason: issued.error.reason });
  }

  return ok({ token: issued.value, expiresAt: new Date(exp * 1000).toISOString() });
}

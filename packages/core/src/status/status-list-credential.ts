import { err, ok, type Result } from "../result.js";
import { issueCredential, type CredentialSigner, type SignedCredential } from "../vc/credential.js";
import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  buildStatusListSubject,
} from "./bitstring-status-list.js";

export type IssueStatusListCredentialError = {
  readonly code: "SIGNING_FAILED";
  readonly reason: string;
};

/**
 * Signs a Bitstring Status List credential over `list`. Shared by the
 * revocation service (which builds the list from its database) and the
 * publisher (which keeps the list as its own state), so there is one format.
 *
 * `validUntil` is the issuer's signed promise of how long a verifier may rely
 * on this list (ADR 0014). A foreign verifier requires it; the intra-org vault
 * does not read it.
 */
export async function issueStatusListCredential(params: {
  readonly list: Uint8Array;
  readonly issuerDid: string;
  readonly signer: CredentialSigner;
  /** The list's identity: the credential's `id` and what each agent's entry points at. */
  readonly statusListCredentialUrl: string;
  readonly now: Date;
  readonly validUntil?: Date;
  readonly ttlMs?: number;
}): Promise<Result<SignedCredential, IssueStatusListCredentialError>> {
  const { list, issuerDid, signer, statusListCredentialUrl, now, validUntil, ttlMs } = params;
  const issued = await issueCredential({
    unsignedCredential: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: statusListCredentialUrl,
      type: ["VerifiableCredential", BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
      issuer: issuerDid,
      validFrom: now.toISOString(),
      ...(validUntil === undefined ? {} : { validUntil: validUntil.toISOString() }),
      credentialSubject: {
        ...buildStatusListSubject({
          id: `${statusListCredentialUrl}#list`,
          list,
          ...(ttlMs === undefined ? {} : { ttlMs }),
        }),
      },
    },
    signer,
  });
  if (!issued.ok) return err({ code: "SIGNING_FAILED", reason: issued.error.reason });
  return ok(issued.value);
}

import {
  buildDidWebDocument,
  buildStatusListEntry,
  err,
  issueCredential,
  multibaseToPublicKey,
  ok,
  REGISTRATION_PROOF_TYPE,
  verifyPossessionProof,
  type DidWebDocument,
  type IssueCredentialError,
  type KeyProvider,
  type Result,
  type SignedCredential,
  type UnsignedCredential,
  type VerifyPossessionProofError,
} from "@custos/core";
import { eq } from "drizzle-orm";
import { agents } from "../db/schema.js";
import type { IdentityDb } from "../db/client.js";
import type { AllocateStatusError, StatusAllocator } from "./status-allocator.js";

export interface RegisteredAgent {
  readonly id: string;
  readonly did: string;
  readonly didDocument: DidWebDocument;
  readonly credential: SignedCredential;
}

export type RegisterAgentError =
  | IssueCredentialError
  | AllocateStatusError
  | { readonly code: "INVALID_PUBLIC_KEY" }
  | {
      readonly code: "INVALID_REGISTRATION_PROOF";
      readonly reason: VerifyPossessionProofError["code"];
    }
  | { readonly code: "KEY_ALREADY_REGISTERED" };

/** The identity service's own signing identity, as issuer of every agent credential (ADR 0007). */
export interface Issuer {
  readonly did: string;
  readonly verificationMethodId: string;
  readonly keyProvider: KeyProvider;
  readonly keyId: string;
}

const SECURITY = "https://w3id.org/security#";

// The agent's public key is embedded in `credentialSubject`, so a verifier
// needs only the issuer's key to check both the credential and, later, every
// proof of possession — offline (ADR 0007 decision 2). No bundled context
// defines `publicKeyMultibase` outside a verification-method object, and the
// signing suite refuses undefined terms, so this inline context maps it to
// the security vocabulary's IRI. Inline, so no context is ever fetched.
const AGENT_KEY_CONTEXT = {
  publicKeyMultibase: { "@id": `${SECURITY}publicKeyMultibase`, "@type": `${SECURITY}multibase` },
} as const;

export async function registerAgent(params: {
  readonly db: IdentityDb;
  readonly issuer: Issuer;
  readonly statusAllocator: StatusAllocator;
  readonly domain: string;
  readonly agentId: string;
  readonly request: { readonly publicKey: string; readonly proof: string };
  readonly now: Date;
  readonly proofMaxSkewSeconds: number;
}): Promise<Result<RegisteredAgent, RegisterAgentError>> {
  const { db, issuer, statusAllocator, domain, agentId, request, now } = params;

  // Everything about the request is checked before anything is allocated or
  // signed: a bad request must not consume a status list index.
  const publicKey = multibaseToPublicKey(request.publicKey);
  if (!publicKey.ok) return err({ code: "INVALID_PUBLIC_KEY" });

  const proof = verifyPossessionProof({
    proof: request.proof,
    publicKey: publicKey.value,
    expectedType: REGISTRATION_PROOF_TYPE,
    expectedAudience: issuer.did,
    now,
    maxSkewSeconds: params.proofMaxSkewSeconds,
  });
  if (!proof.ok) return err({ code: "INVALID_REGISTRATION_PROOF", reason: proof.error.code });

  const existing = await db
    .select({ id: agents.id })
    .from(agents)
    .where(eq(agents.publicKeyMultibase, request.publicKey))
    .limit(1);
  if (existing.length > 0) return err({ code: "KEY_ALREADY_REGISTERED" });

  const didDocument = buildDidWebDocument({
    domain,
    path: ["agents", agentId],
    publicKey: publicKey.value,
  });
  const did = didDocument.id;

  // Before the credential is signed, not after: a credential that exists
  // without a status list entry could never be revoked.
  const allocated = await statusAllocator.allocate({ agentId, agentDid: did });
  if (!allocated.ok) return allocated;

  const unsignedCredential: UnsignedCredential = {
    "@context": ["https://www.w3.org/ns/credentials/v2", AGENT_KEY_CONTEXT],
    id: `urn:uuid:${agentId}`,
    type: ["VerifiableCredential"],
    issuer: issuer.did,
    validFrom: now.toISOString(),
    credentialSubject: { id: did, publicKeyMultibase: request.publicKey },
    credentialStatus: buildStatusListEntry({
      statusListCredential: allocated.value.statusListCredential,
      statusListIndex: allocated.value.statusListIndex,
    }),
  };

  const issued = await issueCredential({
    unsignedCredential,
    signer: {
      id: issuer.verificationMethodId,
      sign: (input) => issuer.keyProvider.sign(issuer.keyId, input.data),
    },
  });
  if (!issued.ok) return issued;

  try {
    await db.insert(agents).values({
      id: agentId,
      did,
      publicKeyMultibase: request.publicKey,
      didDocument,
      credential: issued.value,
    });
  } catch (error) {
    // Two concurrent registrations of one key: the unique constraint decides.
    if (isUniqueViolation(error)) return err({ code: "KEY_ALREADY_REGISTERED" });
    throw error;
  }

  return ok({ id: agentId, did, didDocument, credential: issued.value });
}

const PUBLIC_KEY_UNIQUE_CONSTRAINT = "agents_public_key_multibase_unique";

/** Only this key's uniqueness — any other constraint failure is not "already registered". */
function isUniqueViolation(error: unknown): boolean {
  const cause = error instanceof Error && "cause" in error ? error.cause : error;
  return (
    typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    cause.code === "23505" &&
    "constraint" in cause &&
    cause.constraint === PUBLIC_KEY_UNIQUE_CONSTRAINT
  );
}

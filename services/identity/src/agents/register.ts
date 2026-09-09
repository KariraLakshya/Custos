import {
  buildDidWebDocument,
  buildStatusListEntry,
  issueCredential,
  ok,
  type DidWebDocument,
  type IssueCredentialError,
  type KeyProvider,
  type Result,
  type SignedCredential,
  type UnsignedCredential,
} from "@custos/core";
import { agents } from "../db/schema.js";
import type { IdentityDb } from "../db/client.js";
import type { AllocateStatusError, StatusAllocator } from "./status-allocator.js";

export interface RegisteredAgent {
  readonly id: string;
  readonly did: string;
  readonly didDocument: DidWebDocument;
  readonly credential: SignedCredential;
}

export type RegisterAgentError = IssueCredentialError | AllocateStatusError;

export async function registerAgent(params: {
  readonly db: IdentityDb;
  readonly keyProvider: KeyProvider;
  readonly statusAllocator: StatusAllocator;
  readonly domain: string;
  readonly agentId: string;
  readonly now: Date;
}): Promise<Result<RegisteredAgent, RegisterAgentError>> {
  const { db, keyProvider, statusAllocator, domain, agentId, now } = params;

  const { keyId, publicKey } = await keyProvider.createKeyPair();
  const didDocument = buildDidWebDocument({ domain, path: ["agents", agentId], publicKey });
  const did = didDocument.id;
  const verificationMethodId = didDocument.verificationMethod[0].id;

  // Before the credential is signed, not after: a credential that exists
  // without a status list entry could never be revoked.
  const allocated = await statusAllocator.allocate({ agentId, agentDid: did });
  if (!allocated.ok) return allocated;

  const unsignedCredential: UnsignedCredential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: `urn:uuid:${agentId}`,
    type: ["VerifiableCredential"],
    issuer: did,
    validFrom: now.toISOString(),
    credentialSubject: { id: did },
    credentialStatus: buildStatusListEntry({
      statusListCredential: allocated.value.statusListCredential,
      statusListIndex: allocated.value.statusListIndex,
    }),
  };

  const issued = await issueCredential({
    unsignedCredential,
    signer: {
      id: verificationMethodId,
      sign: (input) => keyProvider.sign(keyId, input.data),
    },
  });
  if (!issued.ok) return issued;

  await db.insert(agents).values({
    id: agentId,
    did,
    keyId,
    didDocument,
    credential: issued.value,
  });

  return ok({ id: agentId, did, didDocument, credential: issued.value });
}

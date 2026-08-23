import {
  buildDidWebDocument,
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

export interface RegisteredAgent {
  readonly id: string;
  readonly did: string;
  readonly didDocument: DidWebDocument;
  readonly credential: SignedCredential;
}

export async function registerAgent(params: {
  readonly db: IdentityDb;
  readonly keyProvider: KeyProvider;
  readonly domain: string;
  readonly agentId: string;
  readonly now: Date;
}): Promise<Result<RegisteredAgent, IssueCredentialError>> {
  const { db, keyProvider, domain, agentId, now } = params;

  const { keyId, publicKey } = await keyProvider.createKeyPair();
  const didDocument = buildDidWebDocument({ domain, path: ["agents", agentId], publicKey });
  const did = didDocument.id;
  const verificationMethodId = didDocument.verificationMethod[0].id;

  const unsignedCredential: UnsignedCredential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: `urn:uuid:${agentId}`,
    type: ["VerifiableCredential"],
    issuer: did,
    validFrom: now.toISOString(),
    credentialSubject: { id: did },
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

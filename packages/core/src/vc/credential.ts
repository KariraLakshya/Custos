import jsigs from "jsonld-signatures";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";
import { err, ok, type Result } from "../result.js";
import type { DidWebDocument } from "../did/did-web.js";
import { staticDocumentLoader } from "./document-loader.js";

const { purposes } = jsigs;
const { AssertionProofPurpose } = purposes;

export interface UnsignedCredential {
  readonly "@context": readonly unknown[];
  readonly id: string;
  readonly type: readonly string[];
  readonly issuer: string;
  readonly validFrom: string;
  readonly credentialSubject: Record<string, unknown>;
}

export interface VerifiableCredentialProof {
  readonly type: "Ed25519Signature2020";
  readonly created: string;
  readonly verificationMethod: string;
  readonly proofPurpose: string;
  readonly proofValue: string;
}

export interface SignedCredential extends UnsignedCredential {
  readonly proof: VerifiableCredentialProof;
}

export type IssueCredentialError = { readonly code: "SIGNING_FAILED"; readonly reason: string };

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function verificationFailureReason(error: { readonly message: string } | undefined): string {
  return error?.message ?? "signature verification failed";
}

/**
 * Signs `unsignedCredential` as `unsignedCredential.issuer` (a did:web DID).
 * The signing key is re-derived from `secretKey` for this one call and never
 * returned or retained — Phase 1 replaces this with a KMS-shaped signer that
 * never exposes `secretKey` to this function at all.
 */
export async function issueCredential(params: {
  readonly unsignedCredential: UnsignedCredential;
  readonly secretKey: Uint8Array;
}): Promise<Result<SignedCredential, IssueCredentialError>> {
  try {
    const keyPair = await Ed25519VerificationKey2020.generate({
      seed: params.secretKey,
      controller: params.unsignedCredential.issuer,
    });
    const suite = new Ed25519Signature2020({ key: keyPair });
    const signed = await jsigs.sign(params.unsignedCredential as unknown as object, {
      suite,
      purpose: new AssertionProofPurpose(),
      documentLoader: staticDocumentLoader,
    });
    return ok(signed as SignedCredential);
  } catch (error) {
    return err({ code: "SIGNING_FAILED", reason: errorMessage(error) });
  }
}

export type VerifyCredentialError =
  | { readonly code: "MALFORMED_CREDENTIAL"; readonly reason: string }
  | { readonly code: "UNKNOWN_VERIFICATION_METHOD"; readonly verificationMethod: string }
  | { readonly code: "UNSUPPORTED_KEY_TYPE"; readonly keyType: string }
  | { readonly code: "SIGNATURE_INVALID"; readonly reason: string };

/**
 * Verifies `credential` against a caller-supplied, already-resolved DID
 * document — verification never fetches the issuer itself (see CLAUDE.md
 * section 3, "verification is local and offline-capable"). The matching
 * verification method and the DID document are both passed to the suite
 * and purpose directly (as `key` and `controller`), never resolved through
 * the document loader, which only ever needs to serve bundled `@context`
 * documents.
 */
export async function verifyCredential(params: {
  readonly credential: SignedCredential;
  readonly didDocument: DidWebDocument;
}): Promise<Result<SignedCredential, VerifyCredentialError>> {
  const { credential, didDocument } = params;

  if (!credential.proof || typeof credential.proof.verificationMethod !== "string") {
    return err({
      code: "MALFORMED_CREDENTIAL",
      reason: "missing a usable proof.verificationMethod",
    });
  }

  const verificationMethod = didDocument.verificationMethod.find(
    (method) => method.id === credential.proof.verificationMethod,
  );
  if (!verificationMethod) {
    return err({
      code: "UNKNOWN_VERIFICATION_METHOD",
      verificationMethod: credential.proof.verificationMethod,
    });
  }
  if (verificationMethod.type !== "Ed25519VerificationKey2020") {
    return err({ code: "UNSUPPORTED_KEY_TYPE", keyType: verificationMethod.type });
  }

  try {
    const keyPair = await Ed25519VerificationKey2020.from(verificationMethod);
    const suite = new Ed25519Signature2020({ key: keyPair });
    const result = await jsigs.verify(credential as unknown as object, {
      suite,
      purpose: new AssertionProofPurpose({ controller: didDocument }),
      documentLoader: staticDocumentLoader,
    });
    if (!result.verified) {
      return err({ code: "SIGNATURE_INVALID", reason: verificationFailureReason(result.error) });
    }
    return ok(credential);
  } catch (error) {
    return err({ code: "SIGNATURE_INVALID", reason: errorMessage(error) });
  }
}

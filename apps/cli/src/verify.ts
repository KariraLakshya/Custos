import { readFile } from "node:fs/promises";
import {
  didWebToResolutionUrl,
  verifyCredential,
  type DidWebDocument,
  type SignedCredential,
} from "@custos/core";

export type VerifyOutcome =
  { readonly verified: true } | { readonly verified: false; readonly reason: string };

function isCredentialLike(value: unknown): value is SignedCredential {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { issuer?: unknown }).issuer === "string"
  );
}

/** Reads and parses a credential file. Untrusted input: reject anything that isn't a usable credential shape rather than letting a malformed file reach `didWebToResolutionUrl`. */
export async function loadCredentialFile(path: string): Promise<SignedCredential> {
  const raw = await readFile(path, "utf8");
  const parsed: unknown = JSON.parse(raw);
  if (!isCredentialLike(parsed)) {
    throw new Error(`not a usable credential: ${path} has no "issuer"`);
  }
  return parsed;
}

/**
 * Independent verification: resolves the issuer's DID document fresh over
 * HTTP from its did:web address and checks the credential against it — no
 * shared state with whatever service issued it.
 */
export async function verifyCredentialIndependently(
  credential: SignedCredential,
): Promise<VerifyOutcome> {
  const resolutionUrl = didWebToResolutionUrl(credential.issuer);

  let response: Response;
  try {
    response = await fetch(resolutionUrl);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      verified: false,
      reason: `could not reach issuer DID document (${resolutionUrl}): ${reason}`,
    };
  }
  if (!response.ok) {
    return {
      verified: false,
      reason: `could not resolve issuer DID document (${resolutionUrl}): HTTP ${response.status}`,
    };
  }
  const didDocument = (await response.json()) as DidWebDocument;

  const result = await verifyCredential({ credential, didDocument });
  if (result.ok) return { verified: true };
  return { verified: false, reason: `${result.error.code}: ${JSON.stringify(result.error)}` };
}

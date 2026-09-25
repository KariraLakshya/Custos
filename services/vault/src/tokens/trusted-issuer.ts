import { didWebToResolutionUrl, type DidWebDocument } from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";

export interface TrustedIssuer {
  /** The one issuer whose agent credentials this vault accepts. */
  readonly did: string;
  readonly resolveDidDocument: () => Promise<Result<DidWebDocument, string>>;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * The identity service, pinned by configuration (ADR 0007 decision 2). A
 * credential from any other issuer is refused before anything else is
 * checked: under issuer-signed credentials, trusting whatever DID a
 * credential names would let anyone with a keypair and a domain issue
 * themselves an agent identity.
 *
 * The DID document is resolved once and cached for the process lifetime —
 * one document serves every agent, so token issuance makes no per-request
 * network call. A failure is not cached; the next request retries. As with
 * the revocation issuer, a key rotation needs a vault restart to pick up.
 */
export function createTrustedIssuer(params: {
  readonly did: string;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}): TrustedIssuer {
  const fetchImpl = params.fetchImpl ?? fetch;
  const timeoutMs = params.timeoutMs ?? 5_000;
  let cached: DidWebDocument | null = null;

  return {
    did: params.did,
    async resolveDidDocument() {
      if (cached) return ok(cached);
      const url = didWebToResolutionUrl(params.did);
      try {
        const response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
        if (!response.ok) return err(`${url}: HTTP ${response.status}`);
        const document: unknown = await response.json();
        if (typeof document !== "object" || document === null) {
          return err(`${url}: not a DID document`);
        }
        const { id, verificationMethod } = document as Partial<DidWebDocument>;
        if (id !== params.did) {
          return err(`${url}: document names ${String(id)}, expected ${params.did}`);
        }
        // Typed as a one-element tuple, but this came off the network: check it.
        if (!Array.isArray(verificationMethod) || (verificationMethod as unknown[]).length === 0) {
          return err(`${url}: no verification methods`);
        }
        cached = document as DidWebDocument;
        return ok(cached);
      } catch (error) {
        return err(`${url}: ${errorMessage(error)}`);
      }
    },
  };
}

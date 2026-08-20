import { contexts as credentialsV2Contexts } from "@digitalcredentials/credentials-v2-context";
import ed25519SignatureContext from "ed25519-signature-2020-context";
import securityContext from "@digitalbazaar/security-context";

const KNOWN_CONTEXTS: ReadonlyMap<string, unknown> = new Map<string, unknown>([
  ...credentialsV2Contexts,
  ...ed25519SignatureContext.contexts,
  ...securityContext.contexts,
]);

export const KNOWN_CONTEXT_URLS: readonly string[] = [...KNOWN_CONTEXTS.keys()];

export interface JsonLdDocumentLoaderResult {
  readonly contextUrl: null;
  readonly document: unknown;
  readonly documentUrl: string;
}

/**
 * Resolves only a fixed set of JSON-LD contexts bundled at build time. Never
 * performs network I/O: verification stays local and offline-capable, and a
 * credential can never smuggle in an `@context` URL that makes this process
 * fetch attacker-controlled infrastructure.
 */
export async function staticDocumentLoader(url: string): Promise<JsonLdDocumentLoaderResult> {
  const document = KNOWN_CONTEXTS.get(url);
  if (document === undefined) {
    throw new Error(`Refusing to load unknown JSON-LD document: "${url}"`);
  }
  return { contextUrl: null, document, documentUrl: url };
}

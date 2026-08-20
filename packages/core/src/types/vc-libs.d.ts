// Ambient declarations for third-party JSON-LD / Verifiable Credential
// libraries that ship no TypeScript types of their own. Typed only to the
// surface this package actually calls, not their full API — `any` below is
// an intentional boundary against untyped CJS libraries, not a shortcut.

declare module "base58-universal" {
  export function encode(bytes: Uint8Array): string;
  export function decode(text: string): Uint8Array;
}

declare module "jsonld-signatures" {
  interface VerificationError {
    message: string;
    errors?: Array<{ name?: string; message: string }>;
  }

  interface VerificationResult {
    verified: boolean;
    results?: unknown[];
    error?: VerificationError;
  }

  interface JsonLdDocumentLoaderResult {
    contextUrl: null;
    document: unknown;
    documentUrl: string;
  }

  type DocumentLoader = (url: string) => Promise<JsonLdDocumentLoaderResult>;

  interface AssertionProofPurposeConstructor {
    new (options?: { controller?: unknown }): unknown;
  }

  interface SignOrVerifyOptions {
    suite: unknown;
    purpose: unknown;
    documentLoader: DocumentLoader;
  }

  interface Jsigs {
    sign(document: object, options: SignOrVerifyOptions): Promise<unknown>;
    verify(document: object, options: SignOrVerifyOptions): Promise<VerificationResult>;
    purposes: { AssertionProofPurpose: AssertionProofPurposeConstructor };
  }

  const jsigs: Jsigs;
  export default jsigs;
}

declare module "@digitalbazaar/ed25519-verification-key-2020" {
  interface ExportedEd25519VerificationKey2020 {
    id: string;
    type: "Ed25519VerificationKey2020";
    controller: string;
    publicKeyMultibase: string;
  }

  interface Ed25519Verifier {
    verify(input: { data: Uint8Array; signature: Uint8Array }): Promise<boolean>;
  }

  interface Ed25519Signer {
    sign(input: { data: Uint8Array }): Promise<Uint8Array>;
  }

  export class Ed25519VerificationKey2020 {
    id: string;
    controller: string;
    publicKeyMultibase: string;
    static generate(options: {
      seed?: Uint8Array;
      controller?: string;
      id?: string;
    }): Promise<Ed25519VerificationKey2020>;
    static from(options: unknown): Promise<Ed25519VerificationKey2020>;
    export(options: {
      publicKey?: boolean;
      privateKey?: boolean;
    }): Promise<ExportedEd25519VerificationKey2020>;
    signer(): Ed25519Signer;
    verifier(): Ed25519Verifier;
  }
}

declare module "@digitalbazaar/ed25519-signature-2020" {
  import type { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";

  export class Ed25519Signature2020 {
    constructor(options?: { key?: Ed25519VerificationKey2020 });
  }
}

declare module "ed25519-signature-2020-context" {
  const value: { contexts: Map<string, unknown>; CONTEXT_URL: string };
  export default value;
}

declare module "@digitalbazaar/security-context" {
  const value: { contexts: Map<string, unknown> };
  export default value;
}

declare module "@digitalcredentials/credentials-v2-context" {
  export const contexts: Map<string, unknown>;
}

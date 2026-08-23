import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import { buildDidWebDocument, didWebFromDomain } from "../did/did-web.js";
import {
  errorMessage,
  issueCredential,
  verificationFailureReason,
  verifyCredential,
  type CredentialSigner,
  type UnsignedCredential,
} from "./credential.js";

function signerFor(secretKey: Uint8Array, verificationMethodId: string): CredentialSigner {
  return {
    id: verificationMethodId,
    sign: ({ data }) => Promise.resolve(sign(data, secretKey)),
  };
}

describe("errorMessage", () => {
  it("uses an Error instance's message", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom");
  });

  it("stringifies a non-Error thrown value", () => {
    expect(errorMessage("boom")).toBe("boom");
    expect(errorMessage(42)).toBe("42");
  });
});

describe("verificationFailureReason", () => {
  it("uses the underlying error's message when present", () => {
    expect(verificationFailureReason({ message: "bad signature" })).toBe("bad signature");
  });

  it("falls back to a generic reason when jsonld-signatures reports no error", () => {
    expect(verificationFailureReason(undefined)).toBe("signature verification failed");
  });
});

const CUSTOS_CONTEXT = { custos: "https://custos.dev/ns#", role: "custos:role" };

function makeUnsignedCredential(issuer: string): UnsignedCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2", CUSTOS_CONTEXT],
    id: "urn:uuid:11111111-1111-1111-1111-111111111111",
    type: ["VerifiableCredential"],
    issuer,
    validFrom: "2026-08-19T00:00:00Z",
    credentialSubject: { id: "urn:agent:demo-agent-1", role: "demo" },
  };
}

describe("issueCredential / verifyCredential", () => {
  it("issues a credential and independently verifies it", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const domain = "issuer.example";
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const unsignedCredential = makeUnsignedCredential(didWebFromDomain(domain));
    const signer = signerFor(secretKey, didDocument.verificationMethod[0].id);

    const issued = await issueCredential({ unsignedCredential, signer });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const verified = await verifyCredential({ credential: issued.value, didDocument });
    expect(verified).toEqual({ ok: true, value: issued.value });
  });

  it("rejects a credential whose credentialSubject was tampered with after signing", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const domain = "issuer.example";
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const unsignedCredential = makeUnsignedCredential(didWebFromDomain(domain));
    const signer = signerFor(secretKey, didDocument.verificationMethod[0].id);

    const issued = await issueCredential({ unsignedCredential, signer });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const tampered = structuredClone(issued.value);
    (tampered.credentialSubject as { role: string }).role = "admin";

    const verified = await verifyCredential({ credential: tampered, didDocument });
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.error.code).toBe("SIGNATURE_INVALID");
  });

  it("rejects a credential signed by a key that isn't in the verifier's DID document", async () => {
    const domain = "issuer.example";
    const { publicKey: legitimatePublicKey } = generateKeyPair();
    const { secretKey: attackerSecretKey, publicKey: attackerPublicKey } = generateKeyPair();
    const didDocument = buildDidWebDocument({ domain, publicKey: legitimatePublicKey });
    const attackerDidDocument = buildDidWebDocument({ domain, publicKey: attackerPublicKey });
    const unsignedCredential = makeUnsignedCredential(didWebFromDomain(domain));
    const signer = signerFor(attackerSecretKey, attackerDidDocument.verificationMethod[0].id);

    const issued = await issueCredential({ unsignedCredential, signer });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const verified = await verifyCredential({ credential: issued.value, didDocument });
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.error.code).toBe("UNKNOWN_VERIFICATION_METHOD");
  });

  it("rejects a credential with a missing proof", async () => {
    const { publicKey } = generateKeyPair();
    const domain = "issuer.example";
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const malformed = {
      ...makeUnsignedCredential(didWebFromDomain(domain)),
    } as unknown as Parameters<typeof verifyCredential>[0]["credential"];

    const verified = await verifyCredential({ credential: malformed, didDocument });
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.error.code).toBe("MALFORMED_CREDENTIAL");
  });

  it("rejects a verification method whose declared key type isn't Ed25519VerificationKey2020", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const domain = "issuer.example";
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const unsignedCredential = makeUnsignedCredential(didWebFromDomain(domain));
    const signer = signerFor(secretKey, didDocument.verificationMethod[0].id);

    const issued = await issueCredential({ unsignedCredential, signer });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const wrongKeyTypeDidDocument = structuredClone(didDocument);
    (wrongKeyTypeDidDocument.verificationMethod[0] as { type: string }).type = "JsonWebKey2020";

    const verified = await verifyCredential({
      credential: issued.value,
      didDocument: wrongKeyTypeDidDocument,
    });
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.error.code).toBe("UNSUPPORTED_KEY_TYPE");
  });

  it("fails closed instead of throwing when the DID document's public key material is malformed", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const domain = "issuer.example";
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const unsignedCredential = makeUnsignedCredential(didWebFromDomain(domain));
    const signer = signerFor(secretKey, didDocument.verificationMethod[0].id);

    const issued = await issueCredential({ unsignedCredential, signer });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const corruptedDidDocument = structuredClone(didDocument);
    (
      corruptedDidDocument.verificationMethod[0] as { publicKeyMultibase: string }
    ).publicKeyMultibase = "not-a-key";

    const verified = await verifyCredential({
      credential: issued.value,
      didDocument: corruptedDidDocument,
    });
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.error.code).toBe("SIGNATURE_INVALID");
  });

  it("fails closed instead of throwing when the injected signer rejects", async () => {
    const domain = "issuer.example";
    const unsignedCredential = makeUnsignedCredential(didWebFromDomain(domain));
    const signer: CredentialSigner = {
      id: `${didWebFromDomain(domain)}#unreachable`,
      sign: () => Promise.reject(new Error("KMS unreachable")),
    };

    const issued = await issueCredential({ unsignedCredential, signer });
    expect(issued.ok).toBe(false);
    if (issued.ok) return;
    expect(issued.error.code).toBe("SIGNING_FAILED");
  });
});

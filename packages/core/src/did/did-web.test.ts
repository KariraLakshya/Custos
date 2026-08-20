import { describe, expect, it } from "vitest";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { generateKeyPair } from "../crypto/ed25519.js";
import { buildDidWebDocument, didWebFromDomain, publicKeyToMultibase } from "./did-web.js";

describe("didWebFromDomain", () => {
  it("builds a did:web identifier from a bare domain", () => {
    expect(didWebFromDomain("issuer.example")).toBe("did:web:issuer.example");
  });

  it("percent-encodes a port's colon", () => {
    expect(didWebFromDomain("localhost:3000")).toBe("did:web:localhost%3A3000");
  });
});

describe("publicKeyToMultibase", () => {
  it("matches the reference Ed25519VerificationKey2020 encoding for the same public key", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const reference = await Ed25519VerificationKey2020.generate({ seed: secretKey });
    expect(publicKeyToMultibase(publicKey)).toBe(reference.publicKeyMultibase);
  });

  it("matches the reference encoding across many random keys", async () => {
    for (let i = 0; i < 20; i += 1) {
      const { publicKey, secretKey } = generateKeyPair();
      const reference = await Ed25519VerificationKey2020.generate({ seed: secretKey });
      expect(publicKeyToMultibase(publicKey)).toBe(reference.publicKeyMultibase);
    }
  });
});

describe("buildDidWebDocument", () => {
  it("builds a document whose verification method id matches the reference key's auto-derived id", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const domain = "issuer.example";
    const document = buildDidWebDocument({ domain, publicKey });

    const reference = await Ed25519VerificationKey2020.generate({
      seed: secretKey,
      controller: didWebFromDomain(domain),
    });

    expect(document.id).toBe("did:web:issuer.example");
    expect(document.verificationMethod[0].id).toBe(reference.id);
    expect(document.verificationMethod[0].publicKeyMultibase).toBe(reference.publicKeyMultibase);
    expect(document.assertionMethod).toEqual([document.verificationMethod[0].id]);
  });
});

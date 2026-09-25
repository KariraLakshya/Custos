import { KMSClient } from "@aws-sdk/client-kms";
import {
  buildDidWebDocument,
  generateKeyPair,
  issueCredential,
  publicKeyToMultibase,
  verify,
  verifyCredential,
} from "@custos/core";
import { describe, expect, it } from "vitest";
import { createKmsKeyProvider } from "./kms-key-provider.js";

/**
 * Against real AWS KMS — the one thing the stand-in in kms-key-provider.test.ts
 * cannot prove: that KMS's actual key format and signatures work with Custos's
 * own verification. Opt-in, never in CI: `pnpm --filter @custos/identity
 * test:kms` with CUSTOS_TEST_KMS_KEY_ID set to an existing
 * ECC_NIST_EDWARDS25519 / SIGN_VERIFY key, and AWS credentials allowed
 * kms:GetPublicKey and kms:Sign on it. Creates no keys; costs a few requests.
 */
const keyId = process.env.CUSTOS_TEST_KMS_KEY_ID;

// Run deliberately (`test:kms` sets --mode kms), a missing key id is a
// failure, not a silent skip that reads as "KMS works".
if (process.env.MODE === "kms" && !keyId) {
  describe("real AWS KMS", () => {
    it("needs CUSTOS_TEST_KMS_KEY_ID set to an Ed25519 KMS key id or ARN", () => {
      expect.fail("CUSTOS_TEST_KMS_KEY_ID is not set");
    });
  });
}

describe.skipIf(!keyId)("createKmsKeyProvider against real AWS KMS", () => {
  const provider = createKmsKeyProvider(new KMSClient({}));
  const id = keyId as string;
  const message = new TextEncoder().encode("custos real-KMS check");

  it("returns the key's raw 32-byte Ed25519 public key", async () => {
    expect(await provider.getPublicKey(id)).toHaveLength(32);
  });

  it("signs so that @custos/core verifies — and a different key does not", async () => {
    const publicKey = await provider.getPublicKey(id);
    const signature = await provider.sign(id, message);

    expect(verify(signature, message, publicKey)).toBe(true);
    expect(verify(signature, message, generateKeyPair().publicKey)).toBe(false);
  });

  it("signs an agent credential that verifies against the issuer DID document", async () => {
    const issuer = buildDidWebDocument({
      domain: "identity.custos.example",
      publicKey: await provider.getPublicKey(id),
    });
    const agentKey = publicKeyToMultibase(generateKeyPair().publicKey);
    const issued = await issueCredential({
      unsignedCredential: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          {
            publicKeyMultibase: {
              "@id": "https://w3id.org/security#publicKeyMultibase",
              "@type": "https://w3id.org/security#multibase",
            },
          },
        ],
        id: "urn:uuid:kms-check",
        type: ["VerifiableCredential"],
        issuer: issuer.id,
        validFrom: new Date().toISOString(),
        credentialSubject: {
          id: `${issuer.id}:agents:kms-check`,
          publicKeyMultibase: agentKey,
        },
      },
      signer: {
        id: issuer.verificationMethod[0].id,
        sign: ({ data }) => provider.sign(id, data),
      },
    });
    if (!issued.ok) throw new Error(issued.error.reason);

    expect((await verifyCredential({ credential: issued.value, didDocument: issuer })).ok).toBe(
      true,
    );
  });
});

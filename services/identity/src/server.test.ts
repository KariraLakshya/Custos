import {
  generateKeyPair,
  issueCredential,
  verifyCredential,
  type SignedCredential,
} from "@custos/core";
import { describe, expect, it } from "vitest";
import { buildServer } from "./server.js";

describe("identity service", () => {
  it("responds to /health", async () => {
    const app = buildServer();
    const response = await app.inject({ method: "GET", url: "/health" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "identity" });
  });

  it("serves a did:web document at /.well-known/did.json using the configured domain", async () => {
    const app = buildServer({ didDomain: "identity.custos.example" });
    const response = await app.inject({ method: "GET", url: "/.well-known/did.json" });

    expect(response.statusCode).toBe(200);
    const didDocument = response.json();
    expect(didDocument.id).toBe("did:web:identity.custos.example");
    expect(didDocument.verificationMethod).toHaveLength(1);
    expect(didDocument.verificationMethod[0].type).toBe("Ed25519VerificationKey2020");
  });

  it("serves a did:web document that a credential signed by the same key independently verifies against", async () => {
    // Regression guard: proves the served document is the real, working
    // primitive from @custos/core, not just JSON that looks right.
    const keyPair = generateKeyPair();
    const app = buildServer({ didDomain: "identity.custos.example", keyPair });
    const response = await app.inject({ method: "GET", url: "/.well-known/did.json" });
    const didDocument = response.json();

    const issued = await issueCredential({
      secretKey: keyPair.secretKey,
      unsignedCredential: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: "urn:uuid:22222222-2222-2222-2222-222222222222",
        type: ["VerifiableCredential"],
        issuer: didDocument.id,
        validFrom: "2026-08-19T00:00:00Z",
        credentialSubject: { id: "urn:agent:demo-agent-1" },
      },
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const verified = await verifyCredential({
      credential: issued.value as SignedCredential,
      didDocument,
    });
    expect(verified).toEqual({ ok: true, value: issued.value });
  });
});

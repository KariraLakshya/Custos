import { describe, expect, it } from "vitest";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { generateKeyPair } from "../crypto/ed25519.js";
import {
  buildDidWebDocument,
  didWebFromDomain,
  didWebToResolutionUrl,
  multibaseToPublicKey,
  publicKeyToMultibase,
} from "./did-web.js";

describe("didWebFromDomain", () => {
  it("builds a did:web identifier from a bare domain", () => {
    expect(didWebFromDomain("issuer.example")).toBe("did:web:issuer.example");
  });

  it("percent-encodes a port's colon", () => {
    expect(didWebFromDomain("localhost:3000")).toBe("did:web:localhost%3A3000");
  });

  it("appends path segments for a per-agent identifier", () => {
    expect(didWebFromDomain("issuer.example", ["agents", "42"])).toBe(
      "did:web:issuer.example:agents:42",
    );
  });
});

describe("didWebToResolutionUrl", () => {
  it("resolves a bare-domain DID to its .well-known document over https", () => {
    expect(didWebToResolutionUrl("did:web:issuer.example")).toBe(
      "https://issuer.example/.well-known/did.json",
    );
  });

  it("resolves a path-segmented DID to a path-based document url", () => {
    expect(didWebToResolutionUrl("did:web:issuer.example:agents:42")).toBe(
      "https://issuer.example/agents/42/did.json",
    );
  });

  it("decodes a percent-encoded port and resolves localhost over http", () => {
    expect(didWebToResolutionUrl("did:web:localhost%3A4001:agents:42")).toBe(
      "http://localhost:4001/agents/42/did.json",
    );
  });

  it("rejects a non-did:web identifier", () => {
    expect(() => didWebToResolutionUrl("did:key:abc")).toThrow(/not a did:web DID/);
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

describe("multibaseToPublicKey", () => {
  it("round-trips a public key through publicKeyToMultibase", () => {
    const { publicKey } = generateKeyPair();
    expect(multibaseToPublicKey(publicKeyToMultibase(publicKey))).toEqual({
      ok: true,
      value: publicKey,
    });
  });

  it("decodes the reference Ed25519VerificationKey2020 encoding", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const reference = await Ed25519VerificationKey2020.generate({ seed: secretKey });
    expect(multibaseToPublicKey(reference.publicKeyMultibase)).toEqual({
      ok: true,
      value: publicKey,
    });
  });

  // Untrusted input (an agent submits its key at registration): every
  // malformation is a value, never a throw.
  it.each([
    ["an empty string", ""],
    ["a non-base58btc multibase prefix", "m7QHRlc3Q"],
    ["characters outside base58", "z0OIl"],
    ["a key with the wrong multicodec header", `z${"1".repeat(46)}`],
    ["a truncated key", publicKeyToMultibase(new Uint8Array(32)).slice(0, -4)],
    ["an oversized input", `z${"2".repeat(5000)}`],
  ])("rejects %s", (_label, input) => {
    const result = multibaseToPublicKey(input);
    expect(result.ok).toBe(false);
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

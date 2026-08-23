import { createServer, type Server } from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildDidWebDocument,
  didWebFromDomain,
  generateKeyPair,
  issueCredential,
  sign,
  type UnsignedCredential,
} from "@custos/core";
import { loadCredentialFile, verifyCredentialIndependently } from "./verify.js";

describe("loadCredentialFile", () => {
  it("parses a credential JSON file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "custos-cli-"));
    const path = join(dir, "credential.json");
    await writeFile(path, JSON.stringify({ issuer: "did:web:example" }));

    const credential = await loadCredentialFile(path);
    expect(credential.issuer).toBe("did:web:example");
  });

  it("rejects a file that isn't a usable credential", async () => {
    const dir = await mkdtemp(join(tmpdir(), "custos-cli-"));
    const path = join(dir, "not-a-credential.json");
    await writeFile(path, JSON.stringify({ hello: "world" }));

    await expect(loadCredentialFile(path)).rejects.toThrow(/no "issuer"/);
  });
});

describe("verifyCredentialIndependently", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server?.close(resolve));
    server = undefined;
  });

  it("verifies a real credential against its issuer's served DID document", async () => {
    const port = 4201;
    const domain = `localhost:${port}`;
    const { publicKey, secretKey } = generateKeyPair();
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const verificationMethodId = didDocument.verificationMethod[0].id;

    server = createServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(didDocument));
    });
    await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));

    const unsignedCredential: UnsignedCredential = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:11111111-1111-1111-1111-111111111111",
      type: ["VerifiableCredential"],
      issuer: didWebFromDomain(domain),
      validFrom: "2026-08-19T00:00:00Z",
      credentialSubject: { id: didWebFromDomain(domain) },
    };
    const issued = await issueCredential({
      unsignedCredential,
      signer: {
        id: verificationMethodId,
        sign: ({ data }) => Promise.resolve(sign(data, secretKey)),
      },
    });
    if (!issued.ok) throw new Error("test setup: issuance failed");

    const outcome = await verifyCredentialIndependently(issued.value);
    expect(outcome).toEqual({ verified: true });
  });

  it("fails closed when the issuer's DID document endpoint returns an error status", async () => {
    const port = 4202;
    const domain = `localhost:${port}`;
    server = createServer((_req, res) => {
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));

    const outcome = await verifyCredentialIndependently({
      issuer: didWebFromDomain(domain),
      proof: { verificationMethod: `${didWebFromDomain(domain)}#zKey` },
    } as unknown as Parameters<typeof verifyCredentialIndependently>[0]);

    expect(outcome).toEqual({
      verified: false,
      reason: expect.stringContaining("HTTP 404"),
    });
  });

  it("rejects a credential tampered with after issuance", async () => {
    const port = 4203;
    const domain = `localhost:${port}`;
    const { publicKey, secretKey } = generateKeyPair();
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const verificationMethodId = didDocument.verificationMethod[0].id;

    server = createServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(didDocument));
    });
    await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));

    const unsignedCredential: UnsignedCredential = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:22222222-2222-2222-2222-222222222222",
      type: ["VerifiableCredential"],
      issuer: didWebFromDomain(domain),
      validFrom: "2026-08-19T00:00:00Z",
      credentialSubject: { id: didWebFromDomain(domain) },
    };
    const issued = await issueCredential({
      unsignedCredential,
      signer: {
        id: verificationMethodId,
        sign: ({ data }) => Promise.resolve(sign(data, secretKey)),
      },
    });
    if (!issued.ok) throw new Error("test setup: issuance failed");

    const tampered = structuredClone(issued.value) as typeof issued.value & {
      credentialSubject: { id: string };
    };
    tampered.credentialSubject.id = "did:web:attacker.example";

    const outcome = await verifyCredentialIndependently(tampered);

    expect(outcome).toEqual({
      verified: false,
      reason: expect.stringContaining("SIGNATURE_INVALID"),
    });
  });

  it("fails closed when the issuer's DID document can't be reached", async () => {
    const outcome = await verifyCredentialIndependently({
      issuer: "did:web:localhost%3A4299",
      proof: { verificationMethod: "did:web:localhost%3A4299#zKey" },
    } as unknown as Parameters<typeof verifyCredentialIndependently>[0]);

    expect(outcome.verified).toBe(false);
  });
});

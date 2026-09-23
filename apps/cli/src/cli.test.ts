import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildDidWebDocument,
  didWebFromDomain,
  generateKeyPair,
  issueAuditRecord,
  issueCredential,
  sign,
  type UnsignedCredential,
} from "@custos/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createCli } from "./cli.js";

describe("custos CLI", () => {
  it("reports its name and version", () => {
    const program = createCli();
    let output = "";
    program.exitOverride();
    program.configureOutput({
      writeOut: (str) => {
        output += str;
      },
    });

    expect(() => program.parse(["--version"], { from: "user" })).toThrow();
    expect(output.trim()).toBe("0.0.0");
    expect(program.name()).toBe("custos");
  });

  describe("register", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
      vi.restoreAllMocks();
    });

    it("registers against the identity service and prints the result", async () => {
      server = createServer((_req, res) => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ id: "abc", did: "did:web:example:agents:abc", credential: {} }));
      });
      await new Promise<void>((resolve) => server?.listen(4303, "127.0.0.1", resolve));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await createCli().parseAsync(["register", "--identity-url", "http://127.0.0.1:4303"], {
        from: "user",
      });

      expect(stdout.mock.calls.join("")).toContain('"id": "abc"');
    });

    it("writes the credential to --out when given", async () => {
      server = createServer((_req, res) => {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            id: "abc",
            did: "did:web:example:agents:abc",
            credential: { issuer: "did:web:example" },
          }),
        );
      });
      await new Promise<void>((resolve) => server?.listen(4304, "127.0.0.1", resolve));
      vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const dir = await mkdtemp(join(tmpdir(), "custos-cli-out-"));
      const outPath = join(dir, "credential.json");

      await createCli().parseAsync(
        ["register", "--identity-url", "http://127.0.0.1:4304", "--out", outPath],
        { from: "user" },
      );

      const written = JSON.parse(await readFile(outPath, "utf8"));
      expect(written).toEqual({ issuer: "did:web:example" });
    });
  });

  describe("verify", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("prints a success message for a credential that verifies against its served DID document", async () => {
      const port = 4305;
      const domain = `127.0.0.1:${port}`;
      const { publicKey, secretKey } = generateKeyPair();
      const didDocument = buildDidWebDocument({ domain, publicKey });
      const verificationMethodId = didDocument.verificationMethod[0].id;

      const server = createServer((_req, res) => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(didDocument));
      });
      await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));

      const unsignedCredential: UnsignedCredential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: "urn:uuid:33333333-3333-3333-3333-333333333333",
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

      const dir = await mkdtemp(join(tmpdir(), "custos-cli-verify-"));
      const path = join(dir, "credential.json");
      await writeFile(path, JSON.stringify(issued.value));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      const previousExitCode = process.exitCode;
      process.exitCode = undefined;
      try {
        await createCli().parseAsync(["verify", path], { from: "user" });
        expect(process.exitCode).toBeUndefined();
        expect(stdout.mock.calls.join("")).toContain("verified: credential is authentic");
      } finally {
        process.exitCode = previousExitCode;
        await new Promise((resolve) => server.close(resolve));
      }
    });

    it("prints a rejection and sets exit code 1 for an unverifiable credential", async () => {
      const dir = await mkdtemp(join(tmpdir(), "custos-cli-verify-"));
      const path = join(dir, "credential.json");
      await writeFile(path, JSON.stringify({ issuer: "did:web:localhost%3A4399" }));
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      const previousExitCode = process.exitCode;
      process.exitCode = undefined;
      await createCli().parseAsync(["verify", path], { from: "user" });

      expect(process.exitCode).toBe(1);
      expect(stderr.mock.calls.join("")).toContain("rejected:");
      process.exitCode = previousExitCode;
    });
  });

  describe("grant", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
      vi.restoreAllMocks();
    });

    it("grants an agent access to a tool via the vault and prints the result", async () => {
      let received: { url?: string; body: unknown } | undefined;
      server = createServer((req, res) => {
        let raw = "";
        req.on("data", (chunk) => (raw += chunk));
        req.on("end", () => {
          received = { url: req.url, body: JSON.parse(raw) };
          res.statusCode = 201;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ agentId: "did:web:example:agents:abc", tool: "stripe" }));
        });
      });
      await new Promise<void>((resolve) => server?.listen(4307, "127.0.0.1", resolve));

      const dir = await mkdtemp(join(tmpdir(), "custos-cli-grant-"));
      const path = join(dir, "credential.json");
      await writeFile(path, JSON.stringify({ issuer: "did:web:example:agents:abc" }));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await createCli().parseAsync(
        ["grant", "stripe", "--credential", path, "--vault-url", "http://127.0.0.1:4307"],
        { from: "user" },
      );

      expect(received).toEqual({
        url: "/policies",
        body: { agentId: "did:web:example:agents:abc", tool: "stripe" },
      });
      expect(stdout.mock.calls.join("")).toContain('"tool": "stripe"');
    });
  });

  describe("audit-log", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
      vi.restoreAllMocks();
    });

    it("pulls and prints the independently verified audit log", async () => {
      const port = 4814;
      const domain = `127.0.0.1:${port}`;
      const { publicKey, secretKey } = generateKeyPair();
      const didDocument = buildDidWebDocument({ domain, publicKey });
      const agentDid = "did:web:localhost%3A4001:agents:a1";

      const issued = await issueAuditRecord({
        record: {
          agentDid,
          authorityChain: [agentDid],
          tool: "mock-slack",
          action: "post-message",
          dataCategories: ["messaging-content"],
          policy: { rule: "agent-tool-allowlist", decision: "allow" },
          recordedAt: "2026-09-12T10:00:00.000Z",
        },
        signer: { sign: (data) => Promise.resolve(sign(data, secretKey)) },
      });
      if (!issued.ok) throw new Error("test setup: issuance failed");

      server = createServer((req, res) => {
        res.setHeader("content-type", "application/json");
        if (req.url?.startsWith("/.well-known/did.json")) {
          res.end(JSON.stringify(didDocument));
          return;
        }
        res.end(JSON.stringify({ records: [issued.value] }));
      });
      await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      const previousExitCode = process.exitCode;
      process.exitCode = undefined;
      await createCli().parseAsync(["audit-log", "--audit-url", `http://127.0.0.1:${port}`], {
        from: "user",
      });

      expect(process.exitCode).toBeUndefined();
      expect(stdout.mock.calls.join("")).toContain('"verified": true');
      process.exitCode = previousExitCode;
    });
  });

  describe("deprovision", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
      vi.restoreAllMocks();
    });

    it("revokes the agent against the revocation service and prints the result", async () => {
      let received: { url?: string; body: unknown } | undefined;
      server = createServer((req, res) => {
        let raw = "";
        req.on("data", (chunk) => (raw += chunk));
        req.on("end", () => {
          received = { url: req.url, body: JSON.parse(raw) };
          res.setHeader("content-type", "application/json");
          res.end(
            JSON.stringify({
              agentId: "abc",
              agentDid: "did:web:example:agents:abc",
              statusListIndex: 7,
              revokedAt: "2026-09-09T00:00:00.000Z",
              alreadyRevoked: false,
              broadcast: { delivered: 1, failed: [] },
            }),
          );
        });
      });
      await new Promise<void>((resolve) => server?.listen(4306, "127.0.0.1", resolve));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await createCli().parseAsync(
        ["deprovision", "abc", "--revocation-url", "http://127.0.0.1:4306", "--reason", "test"],
        { from: "user" },
      );

      expect(received).toEqual({
        url: "/revocations",
        body: { agentId: "abc", reason: "test" },
      });
      expect(stdout.mock.calls.join("")).toContain('"alreadyRevoked": false');
    });
  });
});

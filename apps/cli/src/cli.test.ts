import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  buildDidWebDocument,
  didWebFromDomain,
  generateKeyPair,
  issueAuditRecord,
  issueCredential,
  sign,
  type UnsignedCredential,
} from "@custos/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createCli, runCli } from "./cli.js";

// The stub services accept any key; the real check is proven in the e2e suite.
beforeEach(() => {
  vi.stubEnv("CUSTOS_OPERATOR_KEY", "test-operator-key");
  // Never the developer's real ~/.custos/operator.key (ADR 0010).
  vi.stubEnv("CUSTOS_OPERATOR_KEY_FILE", join(tmpdir(), "custos-no-such-dir", "operator.key"));
});

afterEach(() => {
  vi.unstubAllEnvs();
});

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
        res.end(
          JSON.stringify({
            id: "abc",
            did: "did:web:example:agents:abc",
            credential: { issuer: "did:web:example:agents:abc" },
          }),
        );
      });
      await new Promise<void>((resolve) => server?.listen(4303, "127.0.0.1", resolve));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const keyPath = join(await mkdtemp(join(tmpdir(), "custos-cli-key-")), "agent.key");

      await createCli().parseAsync(
        ["register", "--identity-url", "http://127.0.0.1:4303", "--key-out", keyPath],
        { from: "user" },
      );

      const printed = stdout.mock.calls.join("");
      expect(printed).toContain('"id": "abc"');
      expect(printed).toContain(`"keyFile": ${JSON.stringify(keyPath)}`);
      // The private key is written to its own file and never printed.
      const secretKey = (await readFile(keyPath, "utf8")).trim();
      expect(secretKey).toMatch(/^[0-9a-f]{64}$/);
      expect(printed).not.toContain(secretKey);
    });

    it("refuses to overwrite an existing key file, before registering anything", async () => {
      let requests = 0;
      server = createServer((_req, res) => {
        requests += 1;
        res.end();
      });
      await new Promise<void>((resolve) => server?.listen(4305, "127.0.0.1", resolve));
      const keyPath = join(await mkdtemp(join(tmpdir(), "custos-cli-key-")), "agent.key");
      await writeFile(keyPath, "an existing agent's key");

      await expect(
        createCli().parseAsync(
          ["register", "--identity-url", "http://127.0.0.1:4305", "--key-out", keyPath],
          { from: "user" },
        ),
      ).rejects.toThrow(/refusing to overwrite/);

      expect(await readFile(keyPath, "utf8")).toBe("an existing agent's key");
      expect(requests).toBe(0);
    });

    it("leaves no key file behind when registration fails", async () => {
      server = createServer((_req, res) => {
        res.statusCode = 502;
        res.end();
      });
      await new Promise<void>((resolve) => server?.listen(4306, "127.0.0.1", resolve));
      const keyPath = join(await mkdtemp(join(tmpdir(), "custos-cli-key-")), "agent.key");

      await expect(
        createCli().parseAsync(
          ["register", "--identity-url", "http://127.0.0.1:4306", "--key-out", keyPath],
          { from: "user" },
        ),
      ).rejects.toThrow(/register failed/);

      await expect(readFile(keyPath)).rejects.toThrow(/ENOENT/);
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
        [
          "register",
          "--identity-url",
          "http://127.0.0.1:4304",
          "--out",
          outPath,
          "--key-out",
          join(dir, "agent.key"),
        ],
        { from: "user" },
      );

      const written = JSON.parse(await readFile(outPath, "utf8"));
      expect(written).toEqual({ issuer: "did:web:example" });
    });
  });

  describe("operator key (ADR 0008)", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
    });

    it("refuses register, grant and deprovision without CUSTOS_OPERATOR_KEY, sending nothing", async () => {
      vi.stubEnv("CUSTOS_OPERATOR_KEY", "");
      let requests = 0;
      server = createServer((_req, res) => {
        requests += 1;
        res.end();
      });
      await new Promise<void>((resolve) => server?.listen(4310, "127.0.0.1", resolve));
      const dir = await mkdtemp(join(tmpdir(), "custos-cli-opkey-"));
      const keyPath = join(dir, "agent.key");
      const credentialPath = join(dir, "agent.json");
      await writeFile(credentialPath, JSON.stringify({ credentialSubject: { id: "did:web:x" } }));
      const url = "http://127.0.0.1:4310";

      for (const args of [
        ["register", "--identity-url", url, "--key-out", keyPath],
        ["grant", "mock-slack", "--credential", credentialPath, "--vault-url", url],
        ["deprovision", "0f8f6a1e-9c2b-4a3d-8f1e-1b2c3d4e5f60", "--revocation-url", url],
      ]) {
        await expect(createCli().parseAsync(args, { from: "user" })).rejects.toThrow(
          /sign in with `custos login`, or set CUSTOS_OPERATOR_KEY/,
        );
      }
      expect(requests).toBe(0);
      await expect(readFile(keyPath, "utf8")).rejects.toThrow(/ENOENT/);
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
      // Issued by the identity service; the agent is the subject (ADR 0007).
      await writeFile(
        path,
        JSON.stringify({
          issuer: "did:web:example",
          credentialSubject: { id: "did:web:example:agents:abc" },
        }),
      );
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

  describe("use", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
      process.exitCode = undefined;
      vi.restoreAllMocks();
    });

    /** A stand-in vault: `/tokens` and `/call` each answer with the given status and body. */
    async function vaultReplying(replies: {
      tokens: { status: number; body: unknown };
      call?: { status: number; body: unknown };
    }): Promise<{ vaultUrl: string; credentialPath: string }> {
      server = createServer((req, res) => {
        const reply = req.url === "/tokens" ? replies.tokens : replies.call;
        res.statusCode = reply?.status ?? 404;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(reply?.body ?? {}));
      });
      await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("expected a port");
      const dir = await mkdtemp(join(tmpdir(), "custos-cli-use-"));
      const credentialPath = join(dir, "agent.json");
      await writeFile(credentialPath, JSON.stringify({ issuer: "did:web:example:agents:abc" }));
      // As `register` writes it: hex and a trailing newline.
      await writeFile(join(dir, "agent.key"), `${"11".repeat(32)}\n`);
      return { vaultUrl: `http://127.0.0.1:${address.port}`, credentialPath };
    }

    async function runUse(
      vaultUrl: string,
      credentialPath: string,
      keyPath = join(dirname(credentialPath), "agent.key"),
    ): Promise<void> {
      await runCli([
        "node",
        "custos",
        "use",
        "mock-database",
        "query",
        "--credential",
        credentialPath,
        "--key",
        keyPath,
        "--vault-url",
        vaultUrl,
        "--input",
        '{"table":"customers"}',
      ]);
    }

    it("reports a missing key file as one clear line, without contacting the vault", async () => {
      let requests = 0;
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 200, body: { token: "tok_abc" } },
      });
      server?.on("request", () => (requests += 1));
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath, join(dirname(credentialPath), "missing.key"));

      expect(stderr.mock.calls.join("")).toMatch(/^error: .*missing\.key/);
      expect(process.exitCode).toBe(1);
      expect(requests).toBe(0);
    });

    it("rejects a key file that isn't a 32-byte hex key", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 200, body: { token: "tok_abc" } },
      });
      const badKey = join(dirname(credentialPath), "bad.key");
      await writeFile(badKey, "-----BEGIN PRIVATE KEY-----\n");
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath, badKey);

      expect(stderr.mock.calls.join("")).toMatch(/^error: .*not an agent key/);
      expect(process.exitCode).toBe(1);
    });

    it("prints the tool's result when the call is allowed", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 200, body: { token: "tok_abc" } },
        call: { status: 200, body: { result: [{ id: 1 }] } },
      });
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      expect(JSON.parse(stdout.mock.calls.join(""))).toEqual({ result: [{ id: 1 }] });
      expect(process.exitCode).toBeUndefined();
    });

    it("reports a denial as one readable line — the code, not a JSON dump — and exit code 1", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: {
          status: 403,
          body: { error: { code: "AGENT_REVOKED", agentId: "did:web:example:agents:abc" } },
        },
      });
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      expect(stderr.mock.calls.join("")).toBe("denied: AGENT_REVOKED\n");
      expect(stdout).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(1);
    });

    it("reports an expired token as a denial too", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 200, body: { token: "tok_expired" } },
        call: { status: 401, body: { error: { code: "INVALID_TOKEN", reason: "EXPIRED" } } },
      });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      expect(stderr.mock.calls.join("")).toBe("denied: INVALID_TOKEN\n");
      expect(process.exitCode).toBe(1);
    });

    it("reports a non-authorization failure with its detail, since the code alone won't explain it", async () => {
      const upstream = {
        error: { code: "UPSTREAM_ERROR", status: 401, reason: "Invalid API Key" },
      };
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 200, body: { token: "tok_abc" } },
        call: { status: 502, body: upstream },
      });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      expect(stderr.mock.calls.join("")).toBe(
        `failed: UPSTREAM_ERROR (HTTP 502) — ${JSON.stringify(upstream)}\n`,
      );
      expect(process.exitCode).toBe(1);
    });
  });

  describe("runCli", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
      process.exitCode = undefined;
      vi.restoreAllMocks();
    });

    // Regression: a failed command (e.g. a denied call) surfaced as an
    // unhandled rejection with a full Node stack trace instead of one line.
    it("reports a failed command as one line on stderr and exit code 1, no stack trace", async () => {
      server = createServer((_req, res) => {
        res.statusCode = 403;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: { code: "AGENT_REVOKED" } }));
      });
      await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("expected a port");
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runCli([
        "node",
        "custos",
        "deprovision",
        "abc",
        "--revocation-url",
        `http://127.0.0.1:${address.port}`,
      ]);

      const written = stderr.mock.calls.map(([chunk]) => String(chunk)).join("");
      expect(written).toMatch(/^error: deprovision failed: .*403.*AGENT_REVOKED.*\n$/);
      expect(written).not.toMatch(/\n\s+at /);
      expect(process.exitCode).toBe(1);
    });
  });
});

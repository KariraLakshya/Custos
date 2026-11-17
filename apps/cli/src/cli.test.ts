import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  buildDidWebDocument,
  didWebFromDomain,
  generateKeyPair,
  AUDIT_GENESIS_HASH,
  computeAuditEntryHash,
  computeAuditPayloadHash,
  issueAuditSeal,
  serializeAuditRecord,
  issueCredential,
  sign,
  type UnsignedCredential,
} from "@custos/core";
import { REFUSALS } from "@custos/contracts";
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

    it("registers, saves the credential and the key, and says what to do next", async () => {
      server = createServer((_req, res) => {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            id: "3f2b8c1e-1111-4111-8111-111111111111",
            did: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
            credential: { issuer: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111" },
          }),
        );
      });
      await new Promise<void>((resolve) => server?.listen(4303, "127.0.0.1", resolve));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const keyPath = join(await mkdtemp(join(tmpdir(), "custos-cli-key-")), "agent.key");

      await createCli().parseAsync(
        [
          "register",
          "--identity-url",
          "http://127.0.0.1:4303",
          "--key-out",
          keyPath,
          "--out",
          join(dirname(keyPath), "agent.json"),
        ],
        { from: "user" },
      );

      const printed = stdout.mock.calls.join("");
      const credentialPath = join(dirname(keyPath), "agent.json");
      expect(printed).toBe(
        [
          "Registered agent 3f2b8c1e-1111-4111-8111-111111111111.",
          `Its credential is in ${credentialPath} and its private key in ${keyPath}. Keep the key secret.`,
          "Next: custos grant <tool> --to 3f2b8c1e-1111-4111-8111-111111111111",
          "",
        ].join("\n"),
      );
      expect(JSON.parse(await readFile(credentialPath, "utf8"))).toEqual({
        issuer: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
      });
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
          [
            "register",
            "--identity-url",
            "http://127.0.0.1:4305",
            "--key-out",
            keyPath,
            "--out",
            join(dirname(keyPath), "agent.json"),
          ],
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
          [
            "register",
            "--identity-url",
            "http://127.0.0.1:4306",
            "--key-out",
            keyPath,
            "--out",
            join(dirname(keyPath), "agent.json"),
          ],
          { from: "user" },
        ),
      ).rejects.toThrow(/register failed/);

      await expect(readFile(keyPath)).rejects.toThrow(/ENOENT/);
      await expect(readFile(join(dirname(keyPath), "agent.json"))).rejects.toThrow(/ENOENT/);
    });

    it("refuses to overwrite an existing credential file, and leaves no key behind", async () => {
      let requests = 0;
      server = createServer((_req, res) => {
        requests += 1;
        res.end();
      });
      await new Promise<void>((resolve) => server?.listen(4317, "127.0.0.1", resolve));
      const dir = await mkdtemp(join(tmpdir(), "custos-cli-key-"));
      const outPath = join(dir, "agent.json");
      await writeFile(outPath, "an existing agent's credential");
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runCli([
        "node",
        "custos",
        "register",
        "--identity-url",
        "http://127.0.0.1:4317",
        "--key-out",
        join(dir, "agent.key"),
        "--out",
        outPath,
      ]);

      expect(stderr.mock.calls.join("")).toMatch(
        /^error: refusing to overwrite existing credential file .+\nNext: .+--out <path>/,
      );
      expect(process.exitCode).toBe(1);
      process.exitCode = undefined;
      expect(await readFile(outPath, "utf8")).toBe("an existing agent's credential");
      await expect(readFile(join(dir, "agent.key"))).rejects.toThrow(/ENOENT/);
      expect(requests).toBe(0);
    });

    describe("--name (ADR 0022 §2)", () => {
      const ID = "3f2b8c1e-1111-4111-8111-111111111111";

      /** Answers every registration with `reply`; records what was sent. */
      async function identityAnswering(reply: Record<string, unknown>) {
        const bodies: unknown[] = [];
        server = createServer((req, res) => {
          let raw = "";
          req.on("data", (chunk: Buffer) => (raw += chunk.toString()));
          req.on("end", () => {
            bodies.push(raw === "" ? undefined : JSON.parse(raw));
            res.setHeader("content-type", "application/json");
            res.statusCode = 201;
            res.end(
              JSON.stringify({
                id: ID,
                did: `did:web:example:agents:${ID}`,
                credential: { issuer: "did:web:example" },
                ...reply,
              }),
            );
          });
        });
        await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
        const address = server.address();
        if (address === null || typeof address === "string") throw new Error("expected a port");
        return { url: `http://127.0.0.1:${address.port}`, bodies };
      }

      async function files() {
        const dir = await mkdtemp(join(tmpdir(), "custos-cli-name-"));
        return { dir, out: join(dir, "agent.json"), key: join(dir, "agent.key") };
      }

      it("sends the name and prints it beside the id", async () => {
        const { url, bodies } = await identityAnswering({ name: "billing-bot" });
        const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
        const { out, key } = await files();

        await createCli().parseAsync(
          [
            "register",
            "--name",
            "billing-bot",
            "--identity-url",
            url,
            "--out",
            out,
            "--key-out",
            key,
          ],
          { from: "user" },
        );

        expect((bodies[0] as { name?: unknown }).name).toBe("billing-bot");
        expect(stdout.mock.calls.join("").split("\n")[0]).toBe(
          `Registered billing-bot (id ${ID}).`,
        );
        // The credential file holds the signed credential only, never the name.
        expect(await readFile(out, "utf8")).not.toContain("billing-bot");
      });

      it("includes the name in --json output", async () => {
        const { url } = await identityAnswering({ name: "billing-bot" });
        const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
        const { out, key } = await files();

        await createCli().parseAsync(
          [
            "register",
            "--name",
            "billing-bot",
            "--json",
            "--identity-url",
            url,
            "--out",
            out,
            "--key-out",
            key,
          ],
          { from: "user" },
        );

        expect(JSON.parse(stdout.mock.calls.join(""))).toMatchObject({
          id: ID,
          name: "billing-bot",
        });
      });

      it("sends no name without --name", async () => {
        const { url, bodies } = await identityAnswering({ name: null });
        const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
        const { out, key } = await files();

        await createCli().parseAsync(
          ["register", "--identity-url", url, "--out", out, "--key-out", key],
          {
            from: "user",
          },
        );

        expect(bodies[0]).not.toHaveProperty("name");
        expect(stdout.mock.calls.join("").split("\n")[0]).toBe(`Registered agent ${ID}.`);
      });

      it.each([
        ["empty", ""],
        ["too long", "x".repeat(65)],
        ["starting with a dash", "-bot"],
        ["holding a newline", "bot\nRefused: fake"],
        ["non-ASCII", "bøt"],
      ])("refuses a name that is %s, before any file or request", async (_label, name) => {
        const { url, bodies } = await identityAnswering({});
        const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
        const { out, key } = await files();

        await runCli([
          "node",
          "custos",
          "register",
          "--name",
          name,
          "--identity-url",
          url,
          "--out",
          out,
          "--key-out",
          key,
        ]);

        expect(stderr.mock.calls.join("")).toMatch(
          /^error: that name cannot be used\nNext: use 1 to 64 letters/,
        );
        expect(process.exitCode).toBe(1);
        process.exitCode = undefined;
        expect(bodies).toHaveLength(0);
        await expect(readFile(out)).rejects.toThrow(/ENOENT/);
        await expect(readFile(key)).rejects.toThrow(/ENOENT/);
      });

      // Trust boundary: a name off the wire is not printed unless it passes the rule.
      it("does not print a returned name that breaks the rule", async () => {
        const { url } = await identityAnswering({ name: "evil\u001b[2J\nRefused: fake" });
        const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
        const { out, key } = await files();

        await createCli().parseAsync(
          ["register", "--identity-url", url, "--out", out, "--key-out", key],
          {
            from: "user",
          },
        );

        const printed = stdout.mock.calls.join("");
        expect(printed.split("\n")[0]).toBe(`Registered agent ${ID}.`);
        expect(printed).not.toContain("evil");
      });
    });

    it("saves to agent.json and agent.key unless told otherwise", () => {
      const register = createCli().commands.find((command) => command.name() === "register");
      expect(register?.opts()).toMatchObject({ out: "agent.json", keyOut: "agent.key" });
      const use = createCli().commands.find((command) => command.name() === "use");
      expect(use?.opts()).toMatchObject({ credential: "agent.json", key: "agent.key" });
    });

    it("--json prints the old machine-readable result, never the key", async () => {
      server = createServer((_req, res) => {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            id: "3f2b8c1e-1111-4111-8111-111111111111",
            did: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
            credential: { issuer: "did:web:example" },
          }),
        );
      });
      await new Promise<void>((resolve) => server?.listen(4318, "127.0.0.1", resolve));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const dir = await mkdtemp(join(tmpdir(), "custos-cli-key-"));

      await createCli().parseAsync(
        [
          "register",
          "--identity-url",
          "http://127.0.0.1:4318",
          "--json",
          "--key-out",
          join(dir, "agent.key"),
          "--out",
          join(dir, "agent.json"),
        ],
        { from: "user" },
      );

      const printed = stdout.mock.calls.join("");
      expect(JSON.parse(printed)).toMatchObject({
        id: "3f2b8c1e-1111-4111-8111-111111111111",
        keyFile: join(dir, "agent.key"),
      });
      expect(printed).not.toContain((await readFile(join(dir, "agent.key"), "utf8")).trim());
    });

    it("writes the credential to --out when given", async () => {
      server = createServer((_req, res) => {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            id: "3f2b8c1e-1111-4111-8111-111111111111",
            did: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
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
        ["register", "--identity-url", url, "--key-out", keyPath, "--out", `${keyPath}.json`],
        ["grant", "mock-slack", "--credential", credentialPath, "--vault-url", url],
        ["deprovision", "0f8f6a1e-9c2b-4a3d-8f1e-1b2c3d4e5f60", "--revocation-url", url],
      ]) {
        await expect(createCli().parseAsync(args, { from: "user" })).rejects.toThrow(
          /you are not signed in as an operator/,
        );
      }
      expect(requests).toBe(0);
      await expect(readFile(keyPath, "utf8")).rejects.toThrow(/ENOENT/);
      await expect(readFile(`${keyPath}.json`, "utf8")).rejects.toThrow(/ENOENT/);
    });

    it("tells someone who is not signed in to run custos login", async () => {
      vi.stubEnv("CUSTOS_OPERATOR_KEY", "");
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runCli(["node", "custos", "revoke", "3f2b8c1e-1111-4111-8111-111111111111"]);

      expect(stderr.mock.calls.join("")).toMatch(
        /^error: you are not signed in as an operator\nNext: custos login/,
      );
      expect(process.exitCode).toBe(1);
      process.exitCode = undefined;
      vi.restoreAllMocks();
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

    it("grants by credential file (the older way) and says what to do next", async () => {
      let received: { url?: string; body: unknown } | undefined;
      server = createServer((req, res) => {
        let raw = "";
        req.on("data", (chunk) => (raw += chunk));
        req.on("end", () => {
          received = { url: req.url, body: JSON.parse(raw) };
          res.statusCode = 201;
          res.setHeader("content-type", "application/json");
          res.end(
            JSON.stringify({
              agentId: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
              tool: "stripe",
            }),
          );
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
          credentialSubject: { id: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111" },
        }),
      );
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await createCli().parseAsync(
        ["grant", "stripe", "--credential", path, "--vault-url", "http://127.0.0.1:4307"],
        { from: "user" },
      );

      expect(received).toEqual({
        url: "/policies",
        body: {
          agentId: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
          tool: "stripe",
        },
      });
      expect(stdout.mock.calls.join("")).toBe(
        [
          "Agent 3f2b8c1e-1111-4111-8111-111111111111 may now use stripe.",
          "Next, as the agent: custos use stripe <action>",
          "",
        ].join("\n"),
      );
    });

    /** A stand-in vault that records what `grant` sent. */
    async function grantingVault(port: number): Promise<{ bodies: unknown[] }> {
      const bodies: unknown[] = [];
      server = createServer((req, res) => {
        let raw = "";
        req.on("data", (chunk) => (raw += chunk));
        req.on("end", () => {
          const body = JSON.parse(raw) as { agentId: string; tool: string };
          bodies.push(body);
          res.statusCode = 201;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ agentId: body.agentId, tool: body.tool }));
        });
      });
      await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));
      return { bodies };
    }

    // ADR 0022 §7: the operator names the agent; no credential file needed.
    it.each([
      [
        "its id",
        "3f2b8c1e-1111-4111-8111-111111111111",
        "did:web:localhost%3A4001:agents:3f2b8c1e-1111-4111-8111-111111111111",
      ],
      [
        "its DID",
        "did:web:other.example:agents:3f2b8c1e-1111-4111-8111-111111111111",
        "did:web:other.example:agents:3f2b8c1e-1111-4111-8111-111111111111",
      ],
    ])("grants --to an agent named by %s", async (_how, to, did) => {
      const { bodies } = await grantingVault(4319);
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await createCli().parseAsync(
        ["grant", "stripe", "--to", to, "--vault-url", "http://127.0.0.1:4319", "--json"],
        { from: "user" },
      );

      expect(bodies).toEqual([{ agentId: did, tool: "stripe" }]);
      expect(JSON.parse(stdout.mock.calls.join(""))).toEqual({ agentId: did, tool: "stripe" });
    });

    it("turns an id into a DID under --identity-issuer", async () => {
      const { bodies } = await grantingVault(4319);
      vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await createCli().parseAsync(
        [
          "grant",
          "stripe",
          "--to",
          "3f2b8c1e-1111-4111-8111-111111111111",
          "--identity-issuer",
          "did:web:id.company.example",
          "--vault-url",
          "http://127.0.0.1:4319",
        ],
        { from: "user" },
      );

      expect(bodies).toEqual([
        {
          agentId: "did:web:id.company.example:agents:3f2b8c1e-1111-4111-8111-111111111111",
          tool: "stripe",
        },
      ]);
    });

    it.each([
      ["a name", ["--to", "billing-bot"], /not an agent id or DID/],
      [
        "a DID with something after the id",
        ["--to", "did:web:x:agents:3f2b8c1e-1111-4111-8111-111111111111/../admin"],
        /not an agent id or DID/,
      ],
      [
        "an id with a newline",
        ["--to", "3f2b8c1e-1111-4111-8111-111111111111\n"],
        /not an agent id or DID/,
      ],
      ["neither --to nor --credential", [], /say which agent/],
      [
        "both --to and --credential",
        ["--to", "3f2b8c1e-1111-4111-8111-111111111111", "--credential", "x.json"],
        /say which agent/,
      ],
    ])("refuses %s, sending nothing", async (_what, flags, message) => {
      const { bodies } = await grantingVault(4319);

      await expect(
        createCli().parseAsync(
          ["grant", "stripe", ...flags, "--vault-url", "http://127.0.0.1:4319"],
          { from: "user" },
        ),
      ).rejects.toThrow(message);

      expect(bodies).toEqual([]);
    });
  });

  describe("audit-log", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
      vi.restoreAllMocks();
    });

    /** A one-entry sealed ledger, served as the audit service would. */
    async function serveLedger(
      port: number,
      options: { tamper?: boolean; delegated?: boolean } = {},
    ) {
      const { publicKey, secretKey } = generateKeyPair();
      const didDocument = buildDidWebDocument({ domain: `127.0.0.1:${port}`, publicKey });
      const agentDid = "did:web:localhost%3A4001:agents:3f2b8c1e-1111-4111-8111-111111111111";
      const payload = serializeAuditRecord({
        agentDid,
        authorityChain: [agentDid],
        tool: "mock-slack",
        action: "post-message",
        dataCategories: ["messaging-content"],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
        recordedAt: "2026-09-12T10:00:00.000Z",
        // A delegated call with no issuance entry behind it (ADR 0020 §6).
        ...(options.delegated
          ? { authorityChain: ["did:web:localhost%3A4001:agents:a0", agentDid], delegationRef: "r" }
          : {}),
      });
      const payloadHash = computeAuditPayloadHash(payload);
      const issued = await issueAuditSeal({
        seal: {
          log: didDocument.id,
          seq: 1,
          headHash: computeAuditEntryHash({ seq: 1, prevHash: AUDIT_GENESIS_HASH, payloadHash }),
          key: didDocument.verificationMethod[0].publicKeyMultibase,
          sealedAt: "2026-09-12T10:00:10.000Z",
        },
        signer: { sign: (data) => Promise.resolve(sign(data, secretKey)) },
      });
      if (!issued.ok) throw new Error("test setup: sealing failed");
      const served = options.tamper ? payload.replace("allow", "deny") : payload;

      server = createServer((req, res) => {
        res.setHeader("content-type", "application/json");
        if (req.url?.startsWith("/.well-known/did.json")) {
          res.end(JSON.stringify(didDocument));
          return;
        }
        res.end(
          JSON.stringify({
            entries: [{ seq: 1, payload: served, payloadHash }],
            seal: issued.value,
          }),
        );
      });
      await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));
    }

    async function runAuditLog(port: number, extra: string[] = [], sealFileIn?: string) {
      const sealFile =
        sealFileIn ?? join(await mkdtemp(join(tmpdir(), "custos-audit-")), "seal.json");
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
      const previousExitCode = process.exitCode;
      process.exitCode = undefined;
      await createCli().parseAsync(
        ["audit-log", "--audit-url", `http://127.0.0.1:${port}`, "--seal-file", sealFile, ...extra],
        { from: "user" },
      );
      const exitCode = process.exitCode;
      process.exitCode = previousExitCode;
      const result = { exitCode, out: stdout.mock.calls.join(""), err: stderr.mock.calls.join("") };
      stdout.mockRestore();
      stderr.mockRestore();
      return result;
    }

    it("pulls and prints the independently verified, sealed audit log", async () => {
      await serveLedger(4814);
      const { exitCode, out } = await runAuditLog(4814);
      expect(exitCode).toBeUndefined();
      expect(out).toContain('"verified": true');
      expect(out).toContain('"sealedThrough": 1');
    });

    it("checks delegation chains against the issuer --identity-issuer pins", async () => {
      await serveLedger(4861, { delegated: true });
      // The default pinned issuer (localhost:4001) is not running: the chain
      // cannot be checked, so the log fails rather than passing unchecked.
      const unpinned = await runAuditLog(4861);
      expect(unpinned.exitCode).toBe(1);
      expect(unpinned.err).toContain("DELEGATION_UNCHECKABLE");
      // Pinned to a DID that resolves (this stub serves a document for it), the
      // check runs, and finds the call has no issuance entry.
      const pinned = await runAuditLog(4861, ["--identity-issuer", "did:web:127.0.0.1%3A4861"]);
      expect(pinned.exitCode).toBe(1);
      expect(pinned.err).toContain("DELEGATION_UNLINKED");
    });

    it("after a restart on a new key, explains how to check and accept it, then passes with --accept-key", async () => {
      const sealFile = join(await mkdtemp(join(tmpdir(), "custos-audit-")), "seal.json");
      await serveLedger(4816);
      expect((await runAuditLog(4816, [], sealFile)).exitCode).toBeUndefined();
      await new Promise((resolve) => server?.close(resolve));
      await serveLedger(4816); // same address and log, new key

      const changed = await runAuditLog(4816, [], sealFile);
      expect(changed.exitCode).toBe(1);
      const newKey = /--accept-key (z\S+)/.exec(changed.err)?.[1];
      expect(changed.err).toContain("KEY_CHANGED");
      expect(changed.err).toContain("Do not check it against the service's own DID document");
      expect(newKey).toBeDefined();

      // Repeatable, not variadic: an agent DID after it stays the DID.
      const accepted = await runAuditLog(
        4816,
        [
          "--accept-key",
          newKey!,
          "did:web:localhost%3A4001:agents:3f2b8c1e-1111-4111-8111-111111111111",
        ],
        sealFile,
      );
      expect(accepted.exitCode).toBeUndefined();
      expect(accepted.out).toContain('"post-message"');
    });

    it("exits 1 and names the failure when the log was tampered with", async () => {
      await serveLedger(4815, { tamper: true });
      const { exitCode, err } = await runAuditLog(4815);
      expect(exitCode).toBe(1);
      expect(err).toContain("PAYLOAD_MISMATCH");
    });
  });

  describe("deprovision", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) await new Promise((resolve) => server?.close(resolve));
      server = undefined;
      vi.restoreAllMocks();
    });

    // `revoke` is the name; `deprovision` is the old one and must keep working (ADR 0022 §7).
    it.each(["revoke", "deprovision"])(
      "%s cuts the agent off and prints the result",
      async (name) => {
        let received: { url?: string; body: unknown } | undefined;
        server = createServer((req, res) => {
          let raw = "";
          req.on("data", (chunk) => (raw += chunk));
          req.on("end", () => {
            received = { url: req.url, body: JSON.parse(raw) };
            res.setHeader("content-type", "application/json");
            res.end(
              JSON.stringify({
                agentId: "3f2b8c1e-1111-4111-8111-111111111111",
                agentDid: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
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
          [
            name,
            "3f2b8c1e-1111-4111-8111-111111111111",
            "--revocation-url",
            "http://127.0.0.1:4306",
            "--reason",
            "test",
          ],
          { from: "user" },
        );

        expect(received).toEqual({
          url: "/revocations",
          body: { agentId: "3f2b8c1e-1111-4111-8111-111111111111", reason: "test" },
        });
        expect(stdout.mock.calls.join("")).toBe(
          [
            "Agent 3f2b8c1e-1111-4111-8111-111111111111 is cut off from every tool. This cannot be undone.",
            "Vaults told now: 1.",
            "Next: custos audit-log   (the record shows the cut-off)",
            "",
          ].join("\n"),
        );
      },
    );

    it("takes the agent's DID as well as its id, and sends only the id", async () => {
      const bodies: unknown[] = [];
      server = createServer((req, res) => {
        let raw = "";
        req.on("data", (chunk) => (raw += chunk));
        req.on("end", () => {
          bodies.push(JSON.parse(raw));
          res.setHeader("content-type", "application/json");
          res.end(
            JSON.stringify({
              agentId: "3f2b8c1e-1111-4111-8111-111111111111",
              agentDid: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
              statusListIndex: 7,
              revokedAt: "2026-09-09T00:00:00.000Z",
              alreadyRevoked: true,
              broadcast: { delivered: 0, failed: ["http://vault-2"] },
            }),
          );
        });
      });
      await new Promise<void>((resolve) => server?.listen(4306, "127.0.0.1", resolve));
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await createCli().parseAsync(
        [
          "revoke",
          "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
          "--revocation-url",
          "http://127.0.0.1:4306",
        ],
        { from: "user" },
      );

      expect(bodies).toEqual([{ agentId: "3f2b8c1e-1111-4111-8111-111111111111" }]);
      const printed = stdout.mock.calls.join("");
      expect(printed).toContain("was already cut off");
      // A vault that could not be told is said plainly, not hidden in JSON.
      expect(printed).toMatch(/\nProblem: 1 vault\(s\) could not be told now\./);
      expect(printed).not.toContain("vault-2");
    });

    it("refuses something that is not an id or DID, sending nothing", async () => {
      let requests = 0;
      server = createServer((_req, res) => {
        requests += 1;
        res.end();
      });
      await new Promise<void>((resolve) => server?.listen(4306, "127.0.0.1", resolve));

      await expect(
        createCli().parseAsync(
          ["revoke", "billing-bot", "--revocation-url", "http://127.0.0.1:4306"],
          { from: "user" },
        ),
      ).rejects.toThrow(/not an agent id or DID/);
      expect(requests).toBe(0);
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
      await writeFile(
        credentialPath,
        JSON.stringify({ issuer: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111" }),
      );
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

    it("explains a denial in words, with the next step and the code, and exit code 1", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: {
          status: 403,
          body: {
            error: {
              code: "AGENT_REVOKED",
              agentId: "did:web:example:agents:3f2b8c1e-1111-4111-8111-111111111111",
            },
          },
        },
      });
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      expect(stderr.mock.calls.join("")).toBe(
        [
          "Refused: This agent, or an agent it is acting for, has been cut off from every tool.",
          "Next: A revoked agent cannot be restored. Register a new one with: custos register",
          "Code: AGENT_REVOKED",
          "",
        ].join("\n"),
      );
      expect(stdout).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(1);
    });

    it("fills the tool's name into the next step", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 403, body: { error: { code: "POLICY_DENIED", agentId: "x" } } },
      });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      expect(stderr.mock.calls.join("")).toContain("custos grant mock-database --to <agent id>");
    });

    it("fills the agent's own id into the next step when its credential names it", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 403, body: { error: { code: "POLICY_DENIED", agentId: "x" } } },
      });
      const id = "3f2b8c1e-1111-4111-8111-111111111111";
      await writeFile(
        credentialPath,
        JSON.stringify({
          issuer: "did:web:example",
          credentialSubject: { id: `did:web:example:agents:${id}` },
        }),
      );
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      expect(stderr.mock.calls.join("")).toContain(
        `\nNext: To allow it, an operator runs: custos grant mock-database --to ${id}\n`,
      );
    });

    it("says where the credential should be when agent.json is missing", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 200, body: { token: "t" } },
      });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, join(dirname(credentialPath), "missing.json"));

      expect(stderr.mock.calls.join("")).toMatch(
        /^error: no agent credential at .+missing\.json\nNext: .+--credential <path>/,
      );
      expect(process.exitCode).toBe(1);
    });

    // ADR 0022 §6: a Custos fault is a problem, not a refusal of the agent.
    it("calls an unreachable identity service a problem, not a bad credential", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: {
          status: 503,
          body: { error: { code: "UNVERIFIABLE_ISSUER", reason: "http://x: fetch failed" } },
        },
      });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      const written = stderr.mock.calls.join("");
      expect(written).toMatch(/^Problem: .*The agent is not at fault\.\nNext: /);
      expect(written).toContain("\nCode: UNVERIFIABLE_ISSUER\n");
      expect(process.exitCode).toBe(1);
    });

    it("calls a vault that does not answer a problem, with a next step", async () => {
      const { credentialPath } = await vaultReplying({ tokens: { status: 200, body: {} } });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      // Port 1: nothing listens there.
      await runUse("http://127.0.0.1:1", credentialPath);

      const written = stderr.mock.calls.join("");
      expect(written).toMatch(/^Problem: A Custos service did not answer\.\nNext: /);
      expect(written).toContain("\nCode: SERVICE_UNREACHABLE\n");
      expect(written).not.toMatch(/\n\s+at /);
      expect(process.exitCode).toBe(1);
    });

    it("explains a code it does not know, and never prints what a service sent as a code", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: {
          status: 403,
          body: { error: { code: "\u001b[2JOWNED", reason: "\u001b]0;title\u0007" } },
        },
      });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      const written = stderr.mock.calls.join("");
      expect(written).toMatch(/^Refused: .*does not recognise\.\nNext: .+\nCode: UNKNOWN\n$/);
      expect(written).not.toContain("\u001b");
      expect(written).not.toContain("\u0007");
      expect(process.exitCode).toBe(1);
    });

    // Phase 8b DONE: every refusal path prints a next step.
    it.each(Object.keys(REFUSALS))("%s is explained with a next step", async (code) => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 403, body: { error: { code } } },
      });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      expect(stderr.mock.calls.join("")).toMatch(
        new RegExp(`^(Refused|Problem): .+\\nNext: .+\\nCode: ${code}\\n$`),
      );
      expect(process.exitCode).toBe(1);
    });

    it("reports an expired token as a denial too", async () => {
      const { vaultUrl, credentialPath } = await vaultReplying({
        tokens: { status: 200, body: { token: "tok_expired" } },
        call: { status: 401, body: { error: { code: "INVALID_TOKEN", reason: "EXPIRED" } } },
      });
      const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

      await runUse(vaultUrl, credentialPath);

      // The reason says why the token was refused (here: it expired).
      expect(stderr.mock.calls.join("")).toMatch(
        /^Refused: .+\nNext: Run the command again to get a new token\.\nCode: INVALID_TOKEN \(EXPIRED\)\n$/,
      );
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

      const written = stderr.mock.calls.join("");
      expect(written).toMatch(/^Refused: Custos allowed the call, but the tool itself answered/);
      expect(written).toContain("\nCode: UPSTREAM_ERROR\n");
      expect(written.endsWith(`Detail: HTTP 502 ${JSON.stringify(upstream)}\n`)).toBe(true);
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
    it("prints the lifecycle in order when run with no command", async () => {
      const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

      await runCli(["node", "custos"]);

      const written = stdout.mock.calls.join("");
      const order = ["custos login", "custos register", "custos grant", "custos use"];
      order.push("custos delegate", "custos revoke", "custos audit-log");
      const positions = order.map((command) => written.indexOf(command));
      expect(positions.every((at) => at >= 0)).toBe(true);
      expect([...positions].sort((a, b) => a - b)).toEqual(positions);
      expect(written).toContain("\nNext: custos login\n");
      expect(process.exitCode).toBeUndefined();
    });

    it("still refuses a command that does not exist", async () => {
      const program = createCli()
        .exitOverride()
        .configureOutput({ writeErr: () => {} });
      await expect(program.parseAsync(["no-such-command"], { from: "user" })).rejects.toThrow();
    });

    it("explains a refused operator command in words, no stack trace, exit code 1", async () => {
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
        "3f2b8c1e-1111-4111-8111-111111111111",
        "--revocation-url",
        `http://127.0.0.1:${address.port}`,
      ]);

      const written = stderr.mock.calls.map(([chunk]) => String(chunk)).join("");
      expect(written).toMatch(/^Refused: .+\nNext: .+\nCode: AGENT_REVOKED\n$/);
      expect(written).not.toMatch(/\n\s+at /);
      expect(process.exitCode).toBe(1);
    });
  });
});

describe("delegation (ADR 0020)", () => {
  let server: Server | undefined;
  afterEach(async () => {
    if (server) await new Promise((resolve) => server?.close(resolve));
    server = undefined;
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  const agentKey = generateKeyPair();
  const DELEGATOR = "did:web:localhost%3A4001:agents:3f2b8c1e-1111-4111-8111-111111111111";
  const RECEIVER = "did:web:localhost%3A4001:agents:7a9d4e20-2222-4222-8222-222222222222";

  /** A delegator's credential and key files, as `register` writes them. */
  async function delegatorFiles() {
    const dir = await mkdtemp(join(tmpdir(), "custos-cli-delegate-"));
    const credentialPath = join(dir, "a.json");
    await writeFile(
      credentialPath,
      JSON.stringify({ issuer: "did:web:localhost%3A4001", credentialSubject: { id: DELEGATOR } }),
    );
    const keyPath = join(dir, "a.key");
    await writeFile(keyPath, `${Buffer.from(agentKey.secretKey).toString("hex")}\n`);
    return { dir, credentialPath, keyPath };
  }

  async function run(args: string[]) {
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    await runCli(["node", "custos", ...args]);
    const result = {
      exitCode: process.exitCode,
      out: stdout.mock.calls.join(""),
      err: stderr.mock.calls.join(""),
    };
    stdout.mockRestore();
    stderr.mockRestore();
    process.exitCode = undefined;
    return result;
  }

  const claimsOf = (handOff: string) =>
    JSON.parse(Buffer.from(handOff.split(".")[0]!, "base64url").toString("utf8")) as Record<
      string,
      unknown
    >;

  it("delegate signs a hand-off locally and writes it for the other agent, refusing to overwrite", async () => {
    const { dir, credentialPath, keyPath } = await delegatorFiles();
    const out = join(dir, "delegation.json");
    const args = [
      "delegate",
      "mock-database",
      "query",
      "--to",
      RECEIVER,
      "--credential",
      credentialPath,
      "--key",
      keyPath,
      "--ttl",
      "120",
      "--out",
      out,
    ];
    const first = await run(args);
    expect(first.exitCode).toBeUndefined();
    expect(first.out).toContain(
      "Agent 7a9d4e20-2222-4222-8222-222222222222 may now query on mock-database",
    );
    expect(first.out).toMatch(
      /\nNext, as that agent: custos use mock-database query --delegation /,
    );
    const written = JSON.parse(await readFile(out, "utf8")) as {
      handOffs: string[];
      credentials: unknown[];
    };
    expect(written.credentials).toEqual([
      { issuer: "did:web:localhost%3A4001", credentialSubject: { id: DELEGATOR } },
    ]);
    const claims = claimsOf(written.handOffs[0]!);
    expect(claims).toMatchObject({
      iss: DELEGATOR,
      sub: RECEIVER,
      grants: [{ tool: "mock-database", actions: ["query"] }],
      depth: 0,
    });
    expect((claims.exp as number) - (claims.iat as number)).toBe(120);

    const again = await run(args);
    expect(again.exitCode).toBe(1);
    expect(again.err).toContain(`refusing to overwrite existing file ${out}`);
    expect(again.err).toContain("\nNext: pass --out <path>");

    // ADR 0022 §7: the receiver named by its id gives the very same hand-off target.
    const byId = join(dir, "by-id.json");
    const third = await run([
      "delegate",
      "mock-database",
      "query",
      "--to",
      "7a9d4e20-2222-4222-8222-222222222222",
      "--credential",
      credentialPath,
      "--key",
      keyPath,
      "--out",
      byId,
    ]);
    expect(third.exitCode).toBeUndefined();
    const { handOffs } = JSON.parse(await readFile(byId, "utf8")) as { handOffs: string[] };
    expect(claimsOf(handOffs[0]!).sub).toBe(RECEIVER);

    // A name is not a way to pick an agent: names can repeat.
    const byName = await run([
      "delegate",
      "mock-database",
      "query",
      "--to",
      "helper-bot",
      "--credential",
      credentialPath,
      "--key",
      keyPath,
      "--out",
      join(dir, "by-name.json"),
    ]);
    expect(byName.exitCode).toBe(1);
    expect(byName.err).toMatch(/^error: that is not an agent id or DID\nNext: /);
    await expect(readFile(join(dir, "by-name.json"))).rejects.toThrow(/ENOENT/);
  });

  it("delegate --extending passes on a received delegation, one depth less", async () => {
    const { dir, credentialPath, keyPath } = await delegatorFiles();
    const first = join(dir, "first.json");
    const base = ["--credential", credentialPath, "--key", keyPath];
    // A delegates to itself only to have something to extend in one test;
    // the vault, not the CLI, decides whether a chain is acceptable.
    expect(
      (
        await run([
          "delegate",
          "mock-database",
          "query",
          "--to",
          DELEGATOR,
          "--depth",
          "1",
          ...base,
          "--out",
          first,
        ])
      ).exitCode,
    ).toBeUndefined();
    const second = join(dir, "second.json");
    const extended = await run([
      "delegate",
      "mock-database",
      "query",
      "--to",
      RECEIVER,
      "--extending",
      first,
      ...base,
      "--out",
      second,
    ]);
    expect(extended.exitCode).toBeUndefined();
    const written = JSON.parse(await readFile(second, "utf8")) as { handOffs: string[] };
    expect(written.handOffs).toHaveLength(2);
    expect(claimsOf(written.handOffs[1]!)).toMatchObject({ sub: RECEIVER, depth: 0 });
  });

  it.each([
    ["a --ttl that is not a whole number", ["--ttl", "soon"], /--ttl must be a whole number/],
    ["a --depth that is not a whole number", ["--depth", "-1"], /--depth must be a whole number/],
  ])("delegate refuses %s", async (_label, extra, message) => {
    const { dir, credentialPath, keyPath } = await delegatorFiles();
    const { exitCode, err } = await run([
      "delegate",
      "mock-database",
      "query",
      "--to",
      RECEIVER,
      "--credential",
      credentialPath,
      "--key",
      keyPath,
      "--out",
      join(dir, "d.json"),
      ...extra,
    ]);
    expect(exitCode).toBe(1);
    expect(err).toMatch(message);
  });

  /** A stand-in vault recording what each `/tokens` request carried. */
  async function recordingVault(tokens: { status: number; body: unknown }) {
    const bodies: unknown[] = [];
    server = createServer((req, res) => {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => {
        if (req.url === "/tokens") bodies.push(JSON.parse(raw));
        const reply = req.url === "/tokens" ? tokens : { status: 200, body: { result: [] } };
        res.statusCode = reply.status;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(reply.body));
      });
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("expected a port");
    return { vaultUrl: `http://127.0.0.1:${address.port}`, bodies };
  }

  async function useWith(vaultUrl: string, delegationPath: string) {
    const { credentialPath, keyPath } = await delegatorFiles();
    return run([
      "use",
      "mock-database",
      "query",
      "--credential",
      credentialPath,
      "--key",
      keyPath,
      "--vault-url",
      vaultUrl,
      "--delegation",
      delegationPath,
    ]);
  }

  const DELEGATION = { handOffs: ["a.b"], credentials: [{ issuer: "did:web:x" }] };

  it("use --delegation sends the delegation with the token request", async () => {
    const { vaultUrl, bodies } = await recordingVault({ status: 200, body: { token: "t" } });
    const path = join(await mkdtemp(join(tmpdir(), "custos-cli-d-")), "d.json");
    await writeFile(path, JSON.stringify(DELEGATION));
    const { exitCode } = await useWith(vaultUrl, path);
    expect(exitCode).toBeUndefined();
    expect(bodies).toEqual([expect.objectContaining({ delegation: DELEGATION })]);
  });

  it("names why a delegation was refused, not just that it was", async () => {
    const { vaultUrl } = await recordingVault({
      status: 403,
      body: { error: { code: "DELEGATION_DENIED", agentId: RECEIVER, reason: "NOT_COVERED" } },
    });
    const path = join(await mkdtemp(join(tmpdir(), "custos-cli-d-")), "d.json");
    await writeFile(path, JSON.stringify(DELEGATION));
    const { exitCode, err } = await useWith(vaultUrl, path);
    expect(exitCode).toBe(1);
    expect(err).toBe(
      [
        "Refused: The permission passed on does not include this tool or action.",
        "Next: Ask the agent that passed it on to include it: custos delegate mock-database <actions...> --to 3f2b8c1e-1111-4111-8111-111111111111",
        "Code: DELEGATION_DENIED (NOT_COVERED)",
        "",
      ].join("\n"),
    );
  });

  const json = (value: unknown) => JSON.stringify(value);
  it.each([
    ["a missing file", null, /no delegation file at/],
    ["a file that is not JSON", "{nope", /is not JSON/],
    ["JSON null", "null", /needs 1 to 16 hand-offs and credentials/],
    ["no hand-offs", json({ handOffs: [], credentials: [{ issuer: "x" }] }), /needs 1 to 16/],
    [
      "a non-string hand-off",
      json({ handOffs: [7], credentials: [{ issuer: "x" }] }),
      /needs 1 to 16/,
    ],
    [
      "an empty hand-off",
      json({ handOffs: [""], credentials: [{ issuer: "x" }] }),
      /needs 1 to 16/,
    ],
    [
      "a credential with no issuer",
      json({ handOffs: ["a.b"], credentials: [{}] }),
      /needs 1 to 16/,
    ],
    ["a non-object credential", json({ handOffs: ["a.b"], credentials: ["x"] }), /needs 1 to 16/],
    [
      "17 hand-offs",
      json({ handOffs: Array(17).fill("a.b"), credentials: [{ issuer: "x" }] }),
      /needs 1 to 16/,
    ],
    [
      "17 credentials",
      json({ handOffs: ["a.b"], credentials: Array(17).fill({ issuer: "x" }) }),
      /needs 1 to 16/,
    ],
  ])(
    "use --delegation refuses %s as one line, sending nothing",
    async (_label, content, message) => {
      const { vaultUrl, bodies } = await recordingVault({ status: 200, body: { token: "t" } });
      const path = join(await mkdtemp(join(tmpdir(), "custos-cli-d-")), "d.json");
      if (content !== null) await writeFile(path, content);
      const { exitCode, err } = await useWith(vaultUrl, path);
      expect(exitCode).toBe(1);
      expect(err).toMatch(message);
      expect(err.trim().split("\n")).toHaveLength(1);
      expect(bodies).toHaveLength(0);
    },
  );
});

import { createServer, type Server } from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadAgentCredential, useTool } from "./use.js";

describe("loadAgentCredential", () => {
  it("reads and parses a credential file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "custos-cli-use-"));
    const path = join(dir, "credential.json");
    await writeFile(path, JSON.stringify({ issuer: "did:web:example" }));

    const credential = await loadAgentCredential(path);
    expect(credential).toEqual({ issuer: "did:web:example" });
  });
});

describe("useTool", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server?.close(resolve));
    server = undefined;
  });

  it("requests a token then spends it, in order", async () => {
    const requests: Array<{ url?: string; body: unknown }> = [];
    server = createServer((req, res) => {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => {
        requests.push({ url: req.url, body: JSON.parse(raw) });
        res.setHeader("content-type", "application/json");
        if (req.url === "/tokens") {
          res.end(JSON.stringify({ token: "tok_abc", expiresAt: "2026-01-01T00:01:00Z" }));
          return;
        }
        res.end(JSON.stringify({ result: { ok: true } }));
      });
    });
    await new Promise<void>((resolve) => server?.listen(4401, "127.0.0.1", resolve));

    const outcome = await useTool({
      vaultUrl: "http://127.0.0.1:4401",
      credential: { issuer: "did:web:example" } as never,
      tool: "stripe",
      action: "list-customers",
      input: { limit: 5 },
    });

    expect(outcome).toEqual({ result: { ok: true } });
    expect(requests[0]).toEqual({
      url: "/tokens",
      body: { tool: "stripe", action: "list-customers", credential: { issuer: "did:web:example" } },
    });
    expect(requests[1]).toEqual({
      url: "/call",
      body: { token: "tok_abc", action: "list-customers", input: { limit: 5 } },
    });
  });

  it("throws when the vault rejects the token request", async () => {
    server = createServer((_req, res) => {
      res.statusCode = 404;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: { code: "UNKNOWN_TOOL" } }));
    });
    await new Promise<void>((resolve) => server?.listen(4402, "127.0.0.1", resolve));

    await expect(
      useTool({
        vaultUrl: "http://127.0.0.1:4402",
        credential: { issuer: "did:web:example" } as never,
        tool: "no-such-tool",
        action: "x",
      }),
    ).rejects.toThrow(/token request failed.*404/);
  });

  it("throws when the vault rejects the call itself (e.g. an expired token)", async () => {
    server = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/tokens") {
        res.end(JSON.stringify({ token: "tok_expired", expiresAt: "2026-01-01T00:01:00Z" }));
        return;
      }
      res.statusCode = 401;
      res.end(JSON.stringify({ error: { code: "INVALID_TOKEN", reason: "EXPIRED" } }));
    });
    await new Promise<void>((resolve) => server?.listen(4403, "127.0.0.1", resolve));

    await expect(
      useTool({
        vaultUrl: "http://127.0.0.1:4403",
        credential: { issuer: "did:web:example" } as never,
        tool: "stripe",
        action: "list-customers",
      }),
    ).rejects.toThrow(/call failed.*401/);
  });
});

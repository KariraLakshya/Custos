import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { grantToolAccess } from "./grant.js";

describe("grantToolAccess", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server?.close(resolve));
    server = undefined;
  });

  it("posts the agent DID and tool to the vault's /policies endpoint", async () => {
    let received: { url?: string; body: unknown } | undefined;
    server = createServer((req, res) => {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => {
        received = { url: req.url, body: JSON.parse(raw) };
        res.statusCode = 201;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ agentId: "did:web:example:agents:a1", tool: "stripe" }));
      });
    });
    await new Promise<void>((resolve) => server?.listen(4704, "127.0.0.1", resolve));

    const result = await grantToolAccess({
      vaultUrl: "http://127.0.0.1:4704",
      agentDid: "did:web:example:agents:a1",
      tool: "stripe",
    });

    expect(received).toEqual({
      url: "/policies",
      body: { agentId: "did:web:example:agents:a1", tool: "stripe" },
    });
    expect(result).toEqual({ agentId: "did:web:example:agents:a1", tool: "stripe" });
  });

  it("throws when the vault rejects the grant request", async () => {
    server = createServer((_req, res) => {
      res.statusCode = 400;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: "INVALID_INPUT" }));
    });
    await new Promise<void>((resolve) => server?.listen(4705, "127.0.0.1", resolve));

    await expect(
      grantToolAccess({
        vaultUrl: "http://127.0.0.1:4705",
        agentDid: "did:web:example:agents:a1",
        tool: "stripe",
      }),
    ).rejects.toThrow(/grant failed.*400/);
  });
});

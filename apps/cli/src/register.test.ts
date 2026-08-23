import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { registerAgent } from "./register.js";

describe("registerAgent", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server?.close(resolve));
    server = undefined;
  });

  it("posts to /agents and returns the parsed response", async () => {
    server = createServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          id: "abc",
          did: "did:web:example:agents:abc",
          didDocument: {},
          credential: {},
        }),
      );
    });
    await new Promise<void>((resolve) => server?.listen(4301, "127.0.0.1", resolve));

    const result = await registerAgent("http://127.0.0.1:4301");
    expect(result.id).toBe("abc");
  });

  it("throws when the identity service responds with an error status", async () => {
    server = createServer((_req, res) => {
      res.statusCode = 500;
      res.end();
    });
    await new Promise<void>((resolve) => server?.listen(4302, "127.0.0.1", resolve));

    await expect(registerAgent("http://127.0.0.1:4302")).rejects.toThrow(/500/);
  });
});

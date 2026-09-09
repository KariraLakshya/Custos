import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { deprovisionAgent } from "./deprovision.js";

describe("deprovisionAgent", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server?.close(resolve));
    server = undefined;
  });

  it("posts the agent id to the revocation service and returns its result", async () => {
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
            statusListIndex: 42,
            revokedAt: "2026-09-09T00:00:00.000Z",
            alreadyRevoked: false,
            broadcast: { delivered: 1, failed: [] },
          }),
        );
      });
    });
    await new Promise<void>((resolve) => server?.listen(4701, "127.0.0.1", resolve));

    const result = await deprovisionAgent({
      revocationUrl: "http://127.0.0.1:4701",
      agentId: "abc",
    });

    expect(received).toEqual({ url: "/revocations", body: { agentId: "abc" } });
    expect(result.alreadyRevoked).toBe(false);
    expect(result.broadcast).toEqual({ delivered: 1, failed: [] });
  });

  it("includes a reason in the request body when given", async () => {
    let received: unknown;
    server = createServer((req, res) => {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => {
        received = JSON.parse(raw);
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            agentId: "abc",
            agentDid: "did:web:example:agents:abc",
            statusListIndex: 1,
            revokedAt: "2026-09-09T00:00:00.000Z",
            alreadyRevoked: false,
            broadcast: { delivered: 0, failed: [] },
          }),
        );
      });
    });
    await new Promise<void>((resolve) => server?.listen(4702, "127.0.0.1", resolve));

    await deprovisionAgent({
      revocationUrl: "http://127.0.0.1:4702",
      agentId: "abc",
      reason: "compromised",
    });

    expect(received).toEqual({ agentId: "abc", reason: "compromised" });
  });

  it("throws when the revocation service rejects the request", async () => {
    server = createServer((_req, res) => {
      res.statusCode = 404;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: { code: "UNKNOWN_AGENT", agentId: "no-such-agent" } }));
    });
    await new Promise<void>((resolve) => server?.listen(4703, "127.0.0.1", resolve));

    await expect(
      deprovisionAgent({ revocationUrl: "http://127.0.0.1:4703", agentId: "no-such-agent" }),
    ).rejects.toThrow(/deprovision failed.*404/);
  });
});

import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createStripeConnector } from "./stripe.js";

describe("createStripeConnector", () => {
  let server: Server;
  let baseUrl: string;
  let lastAuthHeader: string | undefined;

  beforeEach(async () => {
    server = createServer((req, res) => {
      lastAuthHeader = req.headers.authorization;
      if (req.url?.startsWith("/customers")) {
        if (lastAuthHeader !== "Bearer sk_test_good") {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { message: "Invalid API key" } }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ object: "list", data: [{ id: "cus_1" }] }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("expected a bound port");
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("lists customers using the caller-supplied credential", async () => {
    const connector = createStripeConnector({ baseUrl });
    const result = await connector.call({
      action: "list-customers",
      input: undefined,
      credential: "sk_test_good",
    });

    expect(result).toEqual({ ok: true, value: { object: "list", data: [{ id: "cus_1" }] } });
    expect(lastAuthHeader).toBe("Bearer sk_test_good");
  });

  it("surfaces an upstream rejection (e.g. a bad key) as an error value, not a throw", async () => {
    const connector = createStripeConnector({ baseUrl });
    const result = await connector.call({
      action: "list-customers",
      input: undefined,
      credential: "sk_test_bad",
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("UPSTREAM_ERROR");
      expect(result.error).toMatchObject({ status: 401 });
    }
  });

  it("rejects an unknown action", async () => {
    const connector = createStripeConnector({ baseUrl });
    const result = await connector.call({
      action: "delete-customer",
      input: {},
      credential: "sk_test_good",
    });
    expect(result).toEqual({
      ok: false,
      error: { code: "UNKNOWN_ACTION", action: "delete-customer" },
    });
  });

  it("rejects malformed input", async () => {
    const connector = createStripeConnector({ baseUrl });
    const result = await connector.call({
      action: "list-customers",
      input: { limit: "ten" },
      credential: "sk_test_good",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("INVALID_INPUT");
  });

  it("surfaces a network failure (e.g. the API is unreachable) as an error value", async () => {
    const connector = createStripeConnector({ baseUrl: "http://127.0.0.1:1" });
    const result = await connector.call({
      action: "list-customers",
      input: undefined,
      credential: "sk_test_good",
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("UPSTREAM_ERROR");
  });

  it("revoke() is a documented no-op for this phase", async () => {
    const connector = createStripeConnector({ baseUrl });
    await expect(connector.revoke("agent-1")).resolves.toBeUndefined();
  });
});

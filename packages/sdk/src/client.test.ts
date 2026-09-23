import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createCustos, type Agent } from "./client.js";

interface Reply {
  readonly status?: number;
  /** A string is sent raw (for non-JSON bodies); anything else is JSON-encoded. */
  readonly body?: unknown;
}

interface Recorded {
  readonly url: string | undefined;
  readonly body: unknown;
}

let server: Server | undefined;

afterEach(async () => {
  if (server) await new Promise((resolve) => server?.close(resolve));
  server = undefined;
});

/** One local HTTP server standing in for every Custos service; routes by path. */
async function stubServices(
  routes: Record<string, Reply>,
): Promise<{ url: string; requests: Recorded[] }> {
  const requests: Recorded[] = [];
  server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      requests.push({ url: req.url, body: raw === "" ? undefined : JSON.parse(raw) });
      const reply = routes[req.url ?? ""] ?? { status: 404, body: { error: "NO_ROUTE" } };
      res.statusCode = reply.status ?? 200;
      if (reply.body === undefined) {
        res.end();
      } else if (typeof reply.body === "string") {
        res.end(reply.body);
      } else {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(reply.body));
      }
    });
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected a bound port");
  return { url: `http://127.0.0.1:${address.port}`, requests };
}

function custosAt(url: string) {
  return createCustos({ identityUrl: url, vaultUrl: url, revocationUrl: url });
}

const agent: Agent = {
  id: "abc",
  did: "did:web:example:agents:abc",
  credential: { issuer: "did:web:example:agents:abc", proof: { proofValue: "z123" } },
};

const deprovisioned = {
  agentId: "abc",
  agentDid: "did:web:example:agents:abc",
  statusListIndex: 42,
  revokedAt: "2026-09-24T00:00:00.000Z",
  alreadyRevoked: false,
  broadcast: { delivered: 1, failed: [] },
};

describe("createCustos", () => {
  it("rejects a malformed service URL at construction, not at first request", () => {
    expect(() =>
      createCustos({ identityUrl: "not a url", vaultUrl: "http://x", revocationUrl: "http://x" }),
    ).toThrow();
  });
});

describe("register", () => {
  it("posts to /agents and returns the agent, credential untouched", async () => {
    const credential = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      issuer: "did:web:example:agents:abc",
      credentialSubject: { id: "did:web:example:agents:abc" },
      proof: { type: "DataIntegrityProof", proofValue: "z123" },
    };
    const { url, requests } = await stubServices({
      "/agents": {
        status: 201,
        body: { id: "abc", did: "did:web:example:agents:abc", didDocument: {}, credential },
      },
    });

    const registered = await custosAt(url).register();

    expect(requests).toEqual([{ url: "/agents", body: undefined }]);
    expect(registered.id).toBe("abc");
    expect(registered.did).toBe("did:web:example:agents:abc");
    // The signature covers every field — any reshaping would break verification.
    expect(registered.credential).toEqual(credential);
  });

  it("throws when the identity service responds with an error status", async () => {
    const { url } = await stubServices({ "/agents": { status: 500 } });
    await expect(custosAt(url).register()).rejects.toThrow(/register failed.*500/);
  });

  it("throws on a success response with no credential rather than returning a half-agent", async () => {
    const { url } = await stubServices({
      "/agents": { status: 201, body: { id: "abc", did: "did:web:example:agents:abc" } },
    });
    await expect(custosAt(url).register()).rejects.toThrow(/unexpected response shape/);
  });
});

describe("grant", () => {
  it("allowlists the agent's DID for the tool", async () => {
    const { url, requests } = await stubServices({
      "/policies": { status: 201, body: { agentId: agent.did, tool: "stripe" } },
    });

    const result = await custosAt(url).grant(agent, "stripe");

    expect(requests).toEqual([{ url: "/policies", body: { agentId: agent.did, tool: "stripe" } }]);
    expect(result).toEqual({ agentId: agent.did, tool: "stripe" });
  });

  it("throws when the vault rejects the grant", async () => {
    const { url } = await stubServices({
      "/policies": { status: 400, body: { error: "INVALID_INPUT" } },
    });
    await expect(custosAt(url).grant(agent, "")).rejects.toThrow(/grant failed.*400/);
  });
});

describe("connect(...).call", () => {
  it("requests a scoped token, then spends it, and returns the tool's result", async () => {
    const { url, requests } = await stubServices({
      "/tokens": { body: { token: "tok_abc", expiresAt: "2026-09-24T00:01:00Z" } },
      "/call": { body: { result: [{ id: "cus_1" }] } },
    });

    const stripe = custosAt(url).connect(agent, "stripe");
    const outcome = await stripe.call("list-customers", { limit: 5 });

    expect(stripe.tool).toBe("stripe");
    expect(outcome).toEqual({ ok: true, value: [{ id: "cus_1" }] });
    expect(requests).toEqual([
      {
        url: "/tokens",
        body: { tool: "stripe", action: "list-customers", credential: agent.credential },
      },
      { url: "/call", body: { token: "tok_abc", action: "list-customers", input: { limit: 5 } } },
    ]);
  });

  it("makes no network request on connect alone", async () => {
    const { url, requests } = await stubServices({});
    custosAt(url).connect(agent, "stripe");
    expect(requests).toEqual([]);
  });

  it("requests a fresh token for every call — no token is reused", async () => {
    const { url, requests } = await stubServices({
      "/tokens": { body: { token: "tok_abc" } },
      "/call": { body: { result: null } },
    });

    const tool = custosAt(url).connect(agent, "mock-database");
    await tool.call("query");
    await tool.call("query");

    expect(requests.map((r) => r.url)).toEqual(["/tokens", "/call", "/tokens", "/call"]);
  });

  it("returns a denial, not a throw, when the agent has no grant for the tool", async () => {
    const denial = { error: { code: "POLICY_DENIED", agentId: agent.did } };
    const { url, requests } = await stubServices({ "/tokens": { status: 403, body: denial } });

    const outcome = await custosAt(url).connect(agent, "stripe").call("list-customers");

    expect(outcome).toEqual({
      ok: false,
      error: { stage: "token", status: 403, code: "POLICY_DENIED", detail: denial },
    });
    expect(requests.map((r) => r.url)).toEqual(["/tokens"]);
  });

  it("returns a denial when the agent has been revoked", async () => {
    const { url } = await stubServices({
      "/tokens": { status: 403, body: { error: { code: "AGENT_REVOKED" } } },
    });

    const outcome = await custosAt(url).connect(agent, "stripe").call("list-customers");

    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error.code).toBe("AGENT_REVOKED");
  });

  it("returns a call-stage denial when the vault rejects the token itself (e.g. expired)", async () => {
    const { url } = await stubServices({
      "/tokens": { body: { token: "tok_expired" } },
      "/call": { status: 401, body: { error: { code: "INVALID_TOKEN", reason: "EXPIRED" } } },
    });

    const outcome = await custosAt(url).connect(agent, "stripe").call("list-customers");

    expect(outcome).toEqual({
      ok: false,
      error: {
        stage: "call",
        status: 401,
        code: "INVALID_TOKEN",
        detail: { error: { code: "INVALID_TOKEN", reason: "EXPIRED" } },
      },
    });
  });

  it("reads a bare string error code", async () => {
    const { url } = await stubServices({
      "/tokens": { status: 400, body: { error: "INVALID_INPUT" } },
    });
    const outcome = await custosAt(url).connect(agent, "stripe").call("list-customers");
    expect(outcome.ok === false && outcome.error.code).toBe("INVALID_INPUT");
  });

  it.each([
    ["a non-JSON body", "Bad Gateway"],
    ["an empty body", undefined],
    ["a body with no error field", { message: "nope" }],
    ["an error with a non-string code", { error: { code: 7 } }],
    ["an error that is neither string nor object", { error: 7 }],
  ])("reports code UNKNOWN for %s", async (_label, body) => {
    const { url } = await stubServices({ "/tokens": { status: 502, body } });
    const outcome = await custosAt(url).connect(agent, "stripe").call("list-customers");
    expect(outcome.ok === false && outcome.error).toMatchObject({ status: 502, code: "UNKNOWN" });
  });

  it("fails closed: a success response without a token throws and never reaches /call", async () => {
    const { url, requests } = await stubServices({
      "/tokens": { body: { expiresAt: "2026-09-24T00:01:00Z" } },
      "/call": { body: { result: "should never be reached" } },
    });

    await expect(custosAt(url).connect(agent, "stripe").call("list-customers")).rejects.toThrow(
      /token request failed: unexpected response shape/,
    );
    expect(requests.map((r) => r.url)).toEqual(["/tokens"]);
  });

  it("fails closed: a non-object success response from /call throws", async () => {
    const { url } = await stubServices({
      "/tokens": { body: { token: "tok_abc" } },
      "/call": { body: "not json" },
    });
    await expect(custosAt(url).connect(agent, "stripe").call("list-customers")).rejects.toThrow(
      /call failed: unexpected response shape/,
    );
  });

  it("throws on transport failure — an unreachable vault is not a denial", async () => {
    const { url } = await stubServices({});
    await new Promise((resolve) => server?.close(resolve));
    server = undefined;

    await expect(custosAt(url).connect(agent, "stripe").call("list-customers")).rejects.toThrow();
  });
});

describe("deprovision", () => {
  it("posts the agent id to the revocation service and returns its result", async () => {
    const { url, requests } = await stubServices({ "/revocations": { body: deprovisioned } });

    const result = await custosAt(url).deprovision(agent);

    expect(requests).toEqual([{ url: "/revocations", body: { agentId: "abc" } }]);
    expect(result).toEqual(deprovisioned);
  });

  it("includes a reason when given", async () => {
    const { url, requests } = await stubServices({ "/revocations": { body: deprovisioned } });

    await custosAt(url).deprovision(agent, { reason: "compromised" });

    expect(requests[0]?.body).toEqual({ agentId: "abc", reason: "compromised" });
  });

  it("throws when the revocation service rejects the request", async () => {
    const { url } = await stubServices({
      "/revocations": { status: 404, body: { error: { code: "UNKNOWN_AGENT" } } },
    });
    await expect(custosAt(url).deprovision(agent)).rejects.toThrow(/deprovision failed.*404/);
  });

  it("throws on a malformed success response rather than reporting a revocation that may not have happened", async () => {
    const { url } = await stubServices({ "/revocations": { body: { agentId: "abc" } } });
    await expect(custosAt(url).deprovision(agent)).rejects.toThrow(/unexpected response shape/);
  });
});

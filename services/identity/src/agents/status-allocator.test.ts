import { describe, expect, it, vi } from "vitest";
import { createHttpStatusAllocator } from "./status-allocator.js";

const AGENT = { agentId: "0f8f6a1e-9c2b-4a3d-8f1e-1b2c3d4e5f60", agentDid: "did:web:example:a" };

function jsonResponse(body: unknown, status = 201): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("createHttpStatusAllocator", () => {
  it("reserves an index against the revocation service", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        statusListIndex: 42,
        statusListCredential: "http://127.0.0.1:4503/status/revocation",
      }),
    );
    const allocator = createHttpStatusAllocator({
      revocationUrl: "http://127.0.0.1:4503",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const result = await allocator.allocate(AGENT);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.statusListIndex).toBe(42);
      expect(result.value.statusListCredential).toBe("http://127.0.0.1:4503/status/revocation");
    }
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:4503/agents");
    expect(JSON.parse(String(init.body))).toEqual(AGENT);
  });

  it("normalises a revocation URL with a trailing slash", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ statusListIndex: 0, statusListCredential: "http://x/status/revocation" }),
    );
    const allocator = createHttpStatusAllocator({
      revocationUrl: "http://127.0.0.1:4503/",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await allocator.allocate(AGENT);

    expect((fetchImpl.mock.calls[0] as unknown as [string])[0]).toBe(
      "http://127.0.0.1:4503/agents",
    );
  });

  it("fails closed when the revocation service answers with an error status", async () => {
    const allocator = createHttpStatusAllocator({
      revocationUrl: "http://127.0.0.1:4503",
      fetchImpl: (async () => jsonResponse({ error: "boom" }, 503)) as unknown as typeof fetch,
    });

    const result = await allocator.allocate(AGENT);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("STATUS_ALLOCATION_FAILED");
      expect(result.error.reason).toContain("HTTP 503");
    }
  });

  it("fails closed when the revocation service is unreachable", async () => {
    const allocator = createHttpStatusAllocator({
      revocationUrl: "http://127.0.0.1:4503",
      fetchImpl: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    });

    const result = await allocator.allocate(AGENT);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toContain("ECONNREFUSED");
  });

  it("reports a non-Error transport failure without crashing", async () => {
    const allocator = createHttpStatusAllocator({
      revocationUrl: "http://127.0.0.1:4503",
      fetchImpl: (async () => {
        throw "socket closed";
      }) as unknown as typeof fetch,
    });

    const result = await allocator.allocate(AGENT);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toContain("socket closed");
  });

  // Never invent an index from a malformed reply: a credential pointing at
  // the wrong bit would be revoked by someone else's deprovision, or by
  // nobody at all.
  it.each([
    ["missing statusListIndex", { statusListCredential: "http://x/status/revocation" }],
    ["missing statusListCredential", { statusListIndex: 1 }],
    ["non-numeric index", { statusListIndex: "1", statusListCredential: "http://x" }],
    ["negative index", { statusListIndex: -1, statusListCredential: "http://x" }],
    ["fractional index", { statusListIndex: 1.5, statusListCredential: "http://x" }],
    ["empty credential url", { statusListIndex: 1, statusListCredential: "" }],
    ["null body", null],
  ])("rejects a malformed allocation response (%s)", async (_label, body) => {
    const allocator = createHttpStatusAllocator({
      revocationUrl: "http://127.0.0.1:4503",
      fetchImpl: (async () => jsonResponse(body)) as unknown as typeof fetch,
    });

    const result = await allocator.allocate(AGENT);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toContain("missing");
  });
});

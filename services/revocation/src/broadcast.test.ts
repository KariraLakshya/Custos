import { describe, expect, it, vi } from "vitest";
import { createHttpBroadcaster } from "./broadcast.js";

const TOMBSTONE = "claims.signature";

function okResponse(): Response {
  return new Response(null, { status: 204 });
}

describe("createHttpBroadcaster", () => {
  it("posts the tombstone to every subscriber's /revocations endpoint", async () => {
    const fetchImpl = vi.fn(async () => okResponse());
    const broadcaster = createHttpBroadcaster({
      subscriberUrls: ["http://vault-a:4002", "http://vault-b:4002"],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const outcome = await broadcaster.broadcast(TOMBSTONE);

    expect(outcome).toEqual({ delivered: 2, failed: [] });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://vault-a:4002/revocations");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ tombstone: TOMBSTONE });
  });

  it("normalises a subscriber URL with a trailing slash", async () => {
    const fetchImpl = vi.fn(async () => okResponse());
    const broadcaster = createHttpBroadcaster({
      subscriberUrls: ["http://vault:4002/"],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await broadcaster.broadcast(TOMBSTONE);

    expect((fetchImpl.mock.calls[0] as unknown as [string])[0]).toBe(
      "http://vault:4002/revocations",
    );
  });

  it("reports a subscriber that answers with an error status", async () => {
    const broadcaster = createHttpBroadcaster({
      subscriberUrls: ["http://vault:4002"],
      fetchImpl: (async () => new Response(null, { status: 503 })) as unknown as typeof fetch,
    });

    const outcome = await broadcaster.broadcast(TOMBSTONE);

    expect(outcome.delivered).toBe(0);
    expect(outcome.failed).toHaveLength(1);
    expect(outcome.failed[0]).toContain("HTTP 503");
  });

  it("reports an unreachable subscriber instead of throwing", async () => {
    const broadcaster = createHttpBroadcaster({
      subscriberUrls: ["http://vault:4002"],
      fetchImpl: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    });

    const outcome = await broadcaster.broadcast(TOMBSTONE);

    expect(outcome.delivered).toBe(0);
    expect(outcome.failed[0]).toContain("ECONNREFUSED");
  });

  it("reports a non-Error transport failure without crashing", async () => {
    const broadcaster = createHttpBroadcaster({
      subscriberUrls: ["http://vault:4002"],
      fetchImpl: (async () => {
        throw "socket closed";
      }) as unknown as typeof fetch,
    });

    const outcome = await broadcaster.broadcast(TOMBSTONE);

    expect(outcome.failed[0]).toContain("socket closed");
  });

  // Reaching two of three tools beats reaching none: one dead subscriber
  // must never block delivery to the others.
  it("still delivers to healthy subscribers when one is down", async () => {
    const broadcaster = createHttpBroadcaster({
      subscriberUrls: ["http://dead:4002", "http://healthy:4002"],
      fetchImpl: (async (url: string) => {
        if (url.startsWith("http://dead")) throw new Error("ECONNREFUSED");
        return okResponse();
      }) as unknown as typeof fetch,
    });

    const outcome = await broadcaster.broadcast(TOMBSTONE);

    expect(outcome.delivered).toBe(1);
    expect(outcome.failed).toHaveLength(1);
    expect(outcome.failed[0]).toContain("dead");
  });

  it("is a no-op when no subscribers are registered", async () => {
    const fetchImpl = vi.fn(async () => okResponse());
    const broadcaster = createHttpBroadcaster({
      subscriberUrls: [],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(await broadcaster.broadcast(TOMBSTONE)).toEqual({ delivered: 0, failed: [] });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

import { isRevoked, type TrustAnchor } from "@custos/core";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  issueList,
  makeOrganisation,
  NOW,
  STATUS_FETCH_URL,
  type Organisation,
} from "./fixtures.js";
import { createStatusCache, type StatusCache, type StatusCacheEvent } from "./status-cache.js";

interface Call {
  readonly url: string;
  readonly headers: Record<string, string>;
  readonly redirect: string | undefined;
}

type Reply = Response | ((init: RequestInit) => Promise<Response> | Response);

/** A fetch that answers from a script, one reply per request, and records requests. */
function scriptedFetch(replies: Reply[]): { fetchImpl: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl = ((input: string | URL | Request, init: RequestInit = {}) => {
    calls.push({
      url: String(input),
      headers: { ...(init.headers as Record<string, string>) },
      redirect: init.redirect,
    });
    const reply = replies.shift();
    if (reply === undefined) return Promise.reject(new Error("no scripted reply left"));
    return Promise.resolve(typeof reply === "function" ? reply(init) : reply);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

async function listResponse(
  org: Organisation,
  options: Parameters<typeof issueList>[1] = {},
  headers: Record<string, string> = {},
): Promise<Response> {
  return new Response(JSON.stringify(await issueList(org, options)), {
    status: 200,
    headers: { "content-type": "application/json", ...headers },
  });
}

const created: StatusCache[] = [];

function makeCache(
  org: Organisation,
  fetchImpl: typeof fetch,
  extra: Partial<Parameters<typeof createStatusCache>[0]> = {},
) {
  const events: StatusCacheEvent[] = [];
  const cache = createStatusCache({
    anchors: [org.anchor],
    pollIntervalMs: 60_000,
    maxClockSkewSeconds: 5,
    now: () => NOW,
    fetchImpl,
    onEvent: (event) => events.push(event),
    ...extra,
  });
  created.push(cache);
  return { cache, events };
}

afterEach(async () => {
  await Promise.all(created.splice(0).map((cache) => cache.stop()));
});

const failures = (events: StatusCacheEvent[]) =>
  events.flatMap((event) => (event.kind === "failed" ? [event.reason] : []));

describe("createStatusCache: a verified list becomes the view", () => {
  it("fetches only the configured URL, without following redirects, and keeps the view", async () => {
    const org = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([await listResponse(org, { revoked: [7] })]);
    const { cache, events } = makeCache(org, fetchImpl);

    expect(cache.viewFor(org.anchor)).toBeUndefined();
    await cache.pollOnce(org.anchor);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(STATUS_FETCH_URL);
    expect(calls[0]?.redirect).toBe("error");
    expect(calls[0]?.headers).not.toHaveProperty("if-none-match");
    const view = cache.viewFor(org.anchor);
    expect(view?.statusListId).toBe(org.anchor.statusListId);
    expect(isRevoked(view?.list ?? new Uint8Array(), 7)).toEqual({ ok: true, value: true });
    expect(isRevoked(view?.list ?? new Uint8Array(), 8)).toEqual({ ok: true, value: false });
    expect(events).toEqual([expect.objectContaining({ kind: "updated", domain: "a.example" })]);
  });

  it("answers undefined for an anchor it was not configured with", async () => {
    const org = makeOrganisation();
    const stranger = makeOrganisation({ credentialIssuerDid: "did:web:other.example" });
    const { cache } = makeCache(org, scriptedFetch([]).fetchImpl);
    expect(cache.viewFor(stranger.anchor)).toBeUndefined();
  });

  it("unions revocations across polls and never clears one", async () => {
    const org = makeOrganisation();
    const { fetchImpl } = scriptedFetch([
      await listResponse(org, { revoked: [7] }),
      await listResponse(org, { revoked: [9], now: new Date(NOW.getTime() + 1_000) }),
    ]);
    const { cache } = makeCache(org, fetchImpl, { now: () => new Date(NOW.getTime() + 2_000) });
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    const list = cache.viewFor(org.anchor)?.list ?? new Uint8Array();
    expect(isRevoked(list, 7)).toEqual({ ok: true, value: true });
    expect(isRevoked(list, 9)).toEqual({ ok: true, value: true });
  });

  it("does not let a replayed older list lower the signed freshness", async () => {
    const org = makeOrganisation();
    const newer = new Date(NOW.getTime() + 60_000);
    const { fetchImpl } = scriptedFetch([
      await listResponse(org, { now: newer }),
      await listResponse(org, { now: NOW }),
    ]);
    const { cache } = makeCache(org, fetchImpl, { now: () => new Date(newer.getTime() + 1_000) });
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    expect(cache.viewFor(org.anchor)?.validFrom).toEqual(newer);
  });
});

describe("createStatusCache: nothing unverified is kept", () => {
  it("refuses a list signed by another key and keeps no view", async () => {
    const org = makeOrganisation();
    const other = makeOrganisation();
    const { fetchImpl } = scriptedFetch([
      await listResponse(org, { signWith: other.statusKeys, revoked: [] }),
    ]);
    const { cache, events } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    expect(cache.viewFor(org.anchor)).toBeUndefined();
    expect(failures(events)).toEqual(["LIST_SIGNATURE_INVALID"]);
  });

  it("refuses a tampered list", async () => {
    const org = makeOrganisation();
    const credential = JSON.parse(await (await listResponse(org)).text()) as {
      credentialSubject: { encodedList: string };
    };
    credential.credentialSubject.encodedList = `${credential.credentialSubject.encodedList}A`;
    const { fetchImpl } = scriptedFetch([new Response(JSON.stringify(credential))]);
    const { cache, events } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    expect(cache.viewFor(org.anchor)).toBeUndefined();
    expect(failures(events)).toHaveLength(1);
  });

  it("refuses a correctly signed list that is already stale", async () => {
    const org = makeOrganisation({ maxStatusAgeSeconds: 600 });
    const { fetchImpl } = scriptedFetch([await listResponse(org)]);
    const { cache, events } = makeCache(org, fetchImpl, {
      now: () => new Date(NOW.getTime() + 3_600_000),
    });
    await cache.pollOnce(org.anchor);
    expect(cache.viewFor(org.anchor)).toBeUndefined();
    expect(failures(events)).toEqual(["LIST_STALE"]);
  });

  it.each([
    ["an HTTP error", () => new Response("no", { status: 500 }), "HTTP 500"],
    ["a 404", () => new Response("no", { status: 404 }), "HTTP 404"],
    ["a body that is not JSON", () => new Response("<html>"), undefined],
    ["a body that is not UTF-8", () => new Response(new Uint8Array([0xff, 0xfe, 0xfd])), undefined],
    ["JSON that is not a credential", () => new Response("[1,2,3]"), "LIST_MALFORMED"],
    ["JSON null", () => new Response("null"), "LIST_MALFORMED"],
  ])("keeps no view after %s", async (_label, reply, reason) => {
    const org = makeOrganisation();
    const { fetchImpl } = scriptedFetch([reply()]);
    const { cache, events } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    expect(cache.viewFor(org.anchor)).toBeUndefined();
    expect(failures(events)).toHaveLength(1);
    if (reason !== undefined) expect(failures(events)).toEqual([reason]);
  });

  it("keeps the last verified view when a later poll fails, and does not extend it", async () => {
    const org = makeOrganisation();
    const { fetchImpl } = scriptedFetch([
      await listResponse(org, { revoked: [7] }),
      new Response("down", { status: 503 }),
      new Response("not json"),
    ]);
    const { cache } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    const before = cache.viewFor(org.anchor);
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    expect(cache.viewFor(org.anchor)).toBe(before);
    expect(cache.viewFor(org.anchor)?.notAfter).toEqual(before?.notAfter);
  });

  it("a rejected list cannot lower or clear what was already revoked", async () => {
    const org = makeOrganisation();
    const attacker = makeOrganisation();
    const { fetchImpl } = scriptedFetch([
      await listResponse(org, { revoked: [7] }),
      await listResponse(org, { signWith: attacker.statusKeys }),
    ]);
    const { cache } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    const list = cache.viewFor(org.anchor)?.list ?? new Uint8Array();
    expect(isRevoked(list, 7)).toEqual({ ok: true, value: true });
  });
});

describe("createStatusCache: conditional requests cannot trap B on a stale view", () => {
  it("sends the validators of the last verified body, and treats 304 as 'unchanged' only", async () => {
    const org = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([
      await listResponse(
        org,
        {},
        { etag: '"v1"', "last-modified": "Thu, 22 Oct 2026 12:00:00 GMT" },
      ),
      new Response(null, { status: 304 }),
    ]);
    const { cache, events } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    const view = cache.viewFor(org.anchor);
    await cache.pollOnce(org.anchor);

    expect(calls[1]?.headers["if-none-match"]).toBe('"v1"');
    expect(calls[1]?.headers["if-modified-since"]).toBe("Thu, 22 Oct 2026 12:00:00 GMT");
    // Same object, same signed times: a 304 confirms nothing about freshness.
    expect(cache.viewFor(org.anchor)).toBe(view);
    expect(events.at(-1)).toEqual({ kind: "not-modified", domain: "a.example" });
  });

  it("does not keep the validators of a body that failed verification", async () => {
    const org = makeOrganisation();
    const attacker = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([
      await listResponse(org, {}, { etag: '"good"' }),
      await listResponse(org, { signWith: attacker.statusKeys }, { etag: '"poisoned"' }),
      new Response(null, { status: 304 }),
    ]);
    const { cache } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    expect(calls[2]?.headers["if-none-match"]).toBe('"good"');
  });

  it("never sends a conditional header while it holds no verified view", async () => {
    const org = makeOrganisation();
    const attacker = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([
      await listResponse(org, { signWith: attacker.statusKeys }, { etag: '"poisoned"' }),
      await listResponse(org),
    ]);
    const { cache } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    expect(calls[1]?.headers).not.toHaveProperty("if-none-match");
    expect(calls[1]?.headers).not.toHaveProperty("if-modified-since");
    expect(cache.viewFor(org.anchor)).toBeDefined();
  });

  it("refuses a 304 when it holds no view to confirm", async () => {
    const org = makeOrganisation();
    const { fetchImpl } = scriptedFetch([new Response(null, { status: 304 })]);
    const { cache, events } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    expect(cache.viewFor(org.anchor)).toBeUndefined();
    expect(failures(events)).toEqual(["unexpected 304"]);
  });

  it("drops the old validators when a verified body arrives without any", async () => {
    const org = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([
      await listResponse(org, {}, { etag: '"v1"' }),
      await listResponse(org, { now: new Date(NOW.getTime() + 1_000) }),
      await listResponse(org, { now: new Date(NOW.getTime() + 2_000) }),
    ]);
    const { cache } = makeCache(org, fetchImpl, { now: () => new Date(NOW.getTime() + 3_000) });
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    expect(calls[2]?.headers).not.toHaveProperty("if-none-match");
  });

  it("ignores a validator too long to be real", async () => {
    const org = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([
      await listResponse(org, {}, { etag: `"${"x".repeat(300)}"` }),
      await listResponse(org),
    ]);
    const { cache } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    await cache.pollOnce(org.anchor);
    expect(calls[1]?.headers).not.toHaveProperty("if-none-match");
  });
});

describe("createStatusCache: a hostile host cannot exhaust B", () => {
  it("refuses a body that streams past the cap, whatever Content-Length says", async () => {
    const org = makeOrganisation();
    const chunk = new Uint8Array(1024).fill(0x41);
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        sent += 1;
        controller.enqueue(chunk);
        if (sent > 1000) controller.close();
      },
    });
    const { fetchImpl } = scriptedFetch([new Response(body)]);
    const { cache, events } = makeCache(org, fetchImpl, { maxBodyBytes: 4096 });
    await cache.pollOnce(org.anchor);
    expect(failures(events)).toEqual(["body too large"]);
    // It stopped reading soon after the cap, not after the whole stream.
    expect(sent).toBeLessThan(20);
  });

  it("refuses early when Content-Length already says it is too large", async () => {
    const org = makeOrganisation();
    const { fetchImpl } = scriptedFetch([
      new Response("{}", { headers: { "content-length": "999999999" } }),
    ]);
    const { cache, events } = makeCache(org, fetchImpl, { maxBodyBytes: 4096 });
    await cache.pollOnce(org.anchor);
    expect(failures(events)).toEqual(["body too large"]);
  });

  it("times out a host that answers the headers and then never finishes the body", async () => {
    const org = makeOrganisation();
    const hanging = new ReadableStream<Uint8Array>({ pull: () => new Promise(() => undefined) });
    const { fetchImpl } = scriptedFetch([new Response(hanging)]);
    const { cache, events } = makeCache(org, fetchImpl, { requestTimeoutMs: 50 });
    await cache.pollOnce(org.anchor);
    expect(failures(events)).toEqual(["aborted"]);
  });

  it("times out a host that never answers at all", async () => {
    const org = makeOrganisation();
    const { fetchImpl } = scriptedFetch([
      (init) =>
        new Promise<Response>((_, reject) => {
          init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    ]);
    const { cache, events } = makeCache(org, fetchImpl, { requestTimeoutMs: 50 });
    await cache.pollOnce(org.anchor);
    expect(failures(events)).toEqual(["aborted"]);
  });
});

describe("createStatusCache: real HTTP", () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
    server?.closeAllConnections();
    server = undefined;
  });

  async function serve(handler: Parameters<typeof createServer>[1]): Promise<string> {
    server = createServer(handler);
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${(server?.address() as AddressInfo).port}`;
  }

  it("does not follow a redirect to another URL", async () => {
    const org = makeOrganisation();
    const listJson = JSON.stringify(await issueList(org));
    const hits: string[] = [];
    const base = await serve((request, response) => {
      hits.push(request.url ?? "");
      if (request.url === "/status") {
        response.writeHead(302, { location: "/elsewhere" }).end();
      } else {
        response.writeHead(200, { "content-type": "application/json" }).end(listJson);
      }
    });
    const anchor = { ...org.anchor, statusFetchUrl: `${base}/status` };
    const { cache, events } = makeCache({ ...org, anchor }, fetch);
    await cache.pollOnce(anchor);
    expect(hits).toEqual(["/status"]);
    expect(cache.viewFor(anchor)).toBeUndefined();
    expect(failures(events)).toHaveLength(1);
  });

  it("fetches, verifies and serves a real list, then honours a real 304", async () => {
    const org = makeOrganisation();
    const listJson = JSON.stringify(await issueList(org, { revoked: [3] }));
    const seen: Array<string | undefined> = [];
    const base = await serve((request, response) => {
      seen.push(request.headers["if-none-match"]);
      if (request.headers["if-none-match"] === '"e1"') return void response.writeHead(304).end();
      response.writeHead(200, { etag: '"e1"', "content-type": "application/json" }).end(listJson);
    });
    const anchor = { ...org.anchor, statusFetchUrl: `${base}/status` };
    const { cache } = makeCache({ ...org, anchor }, fetch);
    await cache.pollOnce(anchor);
    const view = cache.viewFor(anchor);
    await cache.pollOnce(anchor);
    expect(seen).toEqual([undefined, '"e1"']);
    expect(cache.viewFor(anchor)).toBe(view);
    expect(isRevoked(view?.list ?? new Uint8Array(), 3)).toEqual({ ok: true, value: true });
  });
});

describe("createStatusCache: polling", () => {
  it("does not poll a disabled anchor", async () => {
    const org = makeOrganisation({ enabled: false });
    const { fetchImpl, calls } = scriptedFetch([await listResponse(org)]);
    const { cache } = makeCache(org, fetchImpl);
    await cache.start();
    await cache.pollOnce(org.anchor);
    expect(calls).toHaveLength(0);
    expect(cache.viewFor(org.anchor)).toBeUndefined();
  });

  it("joins a poll already in flight instead of starting a second fetch", async () => {
    const org = makeOrganisation();
    const response = await listResponse(org);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { fetchImpl, calls } = scriptedFetch([
      async () => {
        await gate;
        return response;
      },
    ]);
    const { cache } = makeCache(org, fetchImpl);
    const first = cache.pollOnce(org.anchor);
    const second = cache.pollOnce(org.anchor);
    release();
    await Promise.all([first, second]);
    expect(calls).toHaveLength(1);
  });

  it("start() resolves after the first round, then keeps polling on the interval", async () => {
    const org = makeOrganisation();
    const replies = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        listResponse(org, { now: new Date(NOW.getTime() + i * 10) }),
      ),
    );
    const { fetchImpl, calls } = scriptedFetch(replies);
    const { cache } = makeCache(org, fetchImpl, {
      pollIntervalMs: 15,
      now: () => new Date(NOW.getTime() + 1_000),
    });
    await cache.start();
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(cache.viewFor(org.anchor)).toBeDefined();
    await vi.waitFor(() => expect(calls.length).toBeGreaterThanOrEqual(3));
  });

  it("start() twice does not start a second set of loops", async () => {
    const org = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([await listResponse(org)]);
    const { cache } = makeCache(org, fetchImpl);
    await cache.start();
    await cache.start();
    expect(calls).toHaveLength(1);
  });

  it("keeps polling after a failed poll", async () => {
    const org = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([
      new Response("down", { status: 503 }),
      await listResponse(org),
    ]);
    const { cache } = makeCache(org, fetchImpl, { pollIntervalMs: 15 });
    await cache.start();
    expect(cache.viewFor(org.anchor)).toBeUndefined();
    await vi.waitFor(() => expect(cache.viewFor(org.anchor)).toBeDefined());
    expect(calls.length).toBeGreaterThanOrEqual(2);
  });

  it("stop() aborts a fetch that is in flight and returns promptly", async () => {
    const org = makeOrganisation();
    let aborted = false;
    const { fetchImpl, calls } = scriptedFetch([
      (init) =>
        new Promise<Response>((_, reject) => {
          init.signal?.addEventListener("abort", () => {
            aborted = true;
            reject(new Error("aborted"));
          });
        }),
    ]);
    const { cache } = makeCache(org, fetchImpl, { requestTimeoutMs: 600_000 });
    void cache.start();
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    const outcome = await Promise.race([
      cache.stop().then(() => "stopped"),
      new Promise((resolve) => setTimeout(() => resolve("hung"), 2_000)),
    ]);
    expect(outcome).toBe("stopped");
    expect(aborted).toBe(true);
  });

  it("stop() does not wait out a long poll interval", async () => {
    const org = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([await listResponse(org)]);
    const { cache } = makeCache(org, fetchImpl, { pollIntervalMs: 3_600_000 });
    await cache.start();
    const outcome = await Promise.race([
      cache.stop().then(() => "stopped"),
      new Promise((resolve) => setTimeout(() => resolve("hung"), 2_000)),
    ]);
    expect(outcome).toBe("stopped");
    expect(calls).toHaveLength(1);
  });

  it("makes no request after stop()", async () => {
    const org = makeOrganisation();
    const { fetchImpl, calls } = scriptedFetch([await listResponse(org), await listResponse(org)]);
    const { cache } = makeCache(org, fetchImpl, { pollIntervalMs: 15 });
    await cache.start();
    await cache.stop();
    const seen = calls.length;
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(calls).toHaveLength(seen);
  });

  it("is not broken by a logging callback that throws", async () => {
    const org = makeOrganisation();
    const { fetchImpl } = scriptedFetch([await listResponse(org)]);
    const { cache } = makeCache(org, fetchImpl, {
      onEvent: () => {
        throw new Error("logger down");
      },
    });
    await cache.pollOnce(org.anchor);
    expect(cache.viewFor(org.anchor)).toBeDefined();
  });

  it.each([0, -1, 1.5, Number.NaN])("refuses a poll interval of %s", (pollIntervalMs) => {
    const org = makeOrganisation();
    expect(() =>
      createStatusCache({
        anchors: [org.anchor],
        pollIntervalMs,
        maxClockSkewSeconds: 5,
        now: () => NOW,
      }),
    ).toThrow("pollIntervalMs");
  });

  it("finds a view by the anchor's credential issuer DID and nothing else", async () => {
    const org = makeOrganisation();
    const { fetchImpl } = scriptedFetch([await listResponse(org)]);
    const { cache } = makeCache(org, fetchImpl);
    await cache.pollOnce(org.anchor);
    const lookalike: TrustAnchor = { ...org.anchor, domain: "evil.example" };
    expect(cache.viewFor(lookalike)).toBeDefined();
    const other: TrustAnchor = { ...org.anchor, credentialIssuerDid: "did:web:evil.example" };
    expect(cache.viewFor(other)).toBeUndefined();
  });
});

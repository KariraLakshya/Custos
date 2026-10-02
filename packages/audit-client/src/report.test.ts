import { describe, expect, it, vi } from "vitest";
import { createHttpAuditReporter, type AuditEvent } from "./report.js";

const SERVICE_KEY = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

const EVENT: AuditEvent = {
  agentDid: "did:web:localhost%3A4001:agents:a1",
  tool: "mock-slack",
  action: "post-message",
  dataCategories: ["messaging-content"],
  policy: { rule: "agent-tool-allowlist", decision: "allow" },
};

/** Waits one microtask tick so the reporter's unawaited fire-and-forget settles. */
async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("createHttpAuditReporter", () => {
  it("posts the event to the audit service's /records endpoint", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 201 }));
    const reporter = createHttpAuditReporter({
      auditUrl: "http://audit:4004",
      serviceKey: SERVICE_KEY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    reporter.report(EVENT);
    await flush();

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://audit:4004/records");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual(EVENT);
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${SERVICE_KEY}`);
  });

  it("normalises an audit URL with a trailing slash", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 201 }));
    const reporter = createHttpAuditReporter({
      auditUrl: "http://audit:4004/",
      serviceKey: SERVICE_KEY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    reporter.report(EVENT);
    await flush();

    expect((fetchImpl.mock.calls[0] as unknown as [string])[0]).toBe("http://audit:4004/records");
  });

  it("returns void immediately — report() never blocks on the network call", () => {
    const reporter = createHttpAuditReporter({
      auditUrl: "http://audit:4004",
      serviceKey: SERVICE_KEY,
      fetchImpl: (() => new Promise(() => {})) as unknown as typeof fetch, // never resolves
    });
    expect(reporter.report(EVENT)).toBeUndefined();
  });

  it("reports an error status through onError instead of throwing", async () => {
    const onError = vi.fn();
    const reporter = createHttpAuditReporter({
      auditUrl: "http://audit:4004",
      serviceKey: SERVICE_KEY,
      fetchImpl: (async () => new Response(null, { status: 503 })) as unknown as typeof fetch,
      onError,
    });

    reporter.report(EVENT);
    await flush();

    expect(onError).toHaveBeenCalledTimes(1);
    expect((onError.mock.calls[0]![0] as Error).message).toContain("HTTP 503");
  });

  it("reports an unreachable audit service through onError instead of throwing", async () => {
    const onError = vi.fn();
    const reporter = createHttpAuditReporter({
      auditUrl: "http://audit:4004",
      serviceKey: SERVICE_KEY,
      fetchImpl: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
      onError,
    });

    reporter.report(EVENT);
    await flush();

    expect((onError.mock.calls[0]![0] as Error).message).toContain("ECONNREFUSED");
  });

  it("does not throw when the audit service is unreachable and no onError is given", async () => {
    const reporter = createHttpAuditReporter({
      auditUrl: "http://audit:4004",
      serviceKey: SERVICE_KEY,
      fetchImpl: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    });

    expect(() => reporter.report(EVENT)).not.toThrow();
    await flush();
  });
});

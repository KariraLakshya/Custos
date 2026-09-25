import { buildDidWebDocument, generateKeyPair } from "@custos/core";
import { describe, expect, it } from "vitest";
import { createTrustedIssuer } from "./trusted-issuer.js";

const DID = "did:web:identity.custos.example";
const document = buildDidWebDocument({
  domain: "identity.custos.example",
  publicKey: generateKeyPair().publicKey,
});

function fetchReturning(...responses: Array<() => Promise<Response>>) {
  const calls: string[] = [];
  const fetchImpl = (async (url: string | URL) => {
    calls.push(String(url));
    const next = responses[Math.min(calls.length - 1, responses.length - 1)];
    if (!next) throw new Error("no response configured");
    return next();
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const serve =
  (body: unknown, status = 200) =>
  () =>
    Promise.resolve(new Response(JSON.stringify(body), { status }));

describe("createTrustedIssuer", () => {
  it("resolves the trusted issuer's DID document from its did:web URL", async () => {
    const { fetchImpl, calls } = fetchReturning(serve(document));
    const issuer = createTrustedIssuer({ did: DID, fetchImpl });

    expect(issuer.did).toBe(DID);
    expect(await issuer.resolveDidDocument()).toEqual({ ok: true, value: document });
    expect(calls).toEqual(["https://identity.custos.example/.well-known/did.json"]);
  });

  it("resolves once and serves every later request from the cache", async () => {
    const { fetchImpl, calls } = fetchReturning(serve(document));
    const issuer = createTrustedIssuer({ did: DID, fetchImpl });

    await issuer.resolveDidDocument();
    await issuer.resolveDidDocument();

    expect(calls).toHaveLength(1);
  });

  it("does not cache a failure — the next request retries", async () => {
    const { fetchImpl, calls } = fetchReturning(serve({}, 503), serve(document));
    const issuer = createTrustedIssuer({ did: DID, fetchImpl });

    expect((await issuer.resolveDidDocument()).ok).toBe(false);
    expect(await issuer.resolveDidDocument()).toEqual({ ok: true, value: document });
    expect(calls).toHaveLength(2);
  });

  it("rejects a document that names a different DID than the one it was fetched for", async () => {
    const other = buildDidWebDocument({
      domain: "attacker.example",
      publicKey: generateKeyPair().publicKey,
    });
    const { fetchImpl } = fetchReturning(serve(other));

    const result = await createTrustedIssuer({ did: DID, fetchImpl }).resolveDidDocument();

    expect(result.ok === false && result.error).toMatch(/names did:web:attacker.example/);
  });

  it.each([
    ["not an object", "just a string"],
    ["no verification methods", { id: DID, verificationMethod: [] }],
  ])("rejects a document that is %s", async (_label, body) => {
    const { fetchImpl } = fetchReturning(serve(body));
    const result = await createTrustedIssuer({ did: DID, fetchImpl }).resolveDidDocument();
    expect(result.ok).toBe(false);
  });

  it("reports an unreachable issuer as a failure value, not a throw", async () => {
    const { fetchImpl } = fetchReturning(() => Promise.reject(new Error("ECONNREFUSED")));
    const result = await createTrustedIssuer({ did: DID, fetchImpl }).resolveDidDocument();
    expect(result.ok === false && result.error).toMatch(/ECONNREFUSED/);
  });

  it("reports a non-Error transport failure too", async () => {
    const { fetchImpl } = fetchReturning(() => Promise.reject("socket hang up"));
    const result = await createTrustedIssuer({ did: DID, fetchImpl }).resolveDidDocument();
    expect(result.ok === false && result.error).toMatch(/socket hang up/);
  });
});

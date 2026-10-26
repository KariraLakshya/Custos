import {
  AUDIT_GENESIS_HASH,
  buildDidWebDocument,
  computeAuditEntryHash,
  computeAuditPayloadHash,
  generateKeyPair,
  issueAuditSeal,
  serializeAuditRecord,
  sign,
} from "@custos/core";
import { describe, expect, it } from "vitest";
import { pullAuditLedger } from "./ledger.js";

const AUDIT_URL = "http://audit.test";
const keys = generateKeyPair();
const did = buildDidWebDocument({ domain: "audit.test", publicKey: keys.publicKey });

async function ledger(actions: readonly string[]) {
  let prevHash = AUDIT_GENESIS_HASH;
  const entries = actions.map((action, index) => {
    const payload = serializeAuditRecord({
      agentDid: "did:web:x:agents:a",
      authorityChain: ["did:web:x:agents:a"],
      action,
      dataCategories: [],
      policy: { rule: "r", decision: "allow" },
      recordedAt: "2026-10-27T10:00:00.000Z",
    });
    const payloadHash = computeAuditPayloadHash(payload);
    prevHash = computeAuditEntryHash({ seq: index + 1, prevHash, payloadHash });
    return { seq: index + 1, payload, payloadHash };
  });
  const issued = await issueAuditSeal({
    seal: { log: did.id, seq: actions.length, headHash: prevHash, sealedAt: "t" },
    signer: { sign: async (data) => sign(data, keys.secretKey) },
  });
  if (!issued.ok) throw new Error("fixture");
  return { entries, seal: issued.value };
}

/** A fetch answering the DID document and `/records` with the given bodies. */
function fakeFetch(
  records: unknown,
  options: { didStatus?: number; recordsStatus?: number; didBody?: unknown } = {},
) {
  const asked: string[] = [];
  const doFetch = (async (input: URL | string) => {
    const url = String(input);
    asked.push(url);
    if (url.endsWith("/.well-known/did.json")) {
      return new Response(JSON.stringify(options.didBody ?? did), {
        status: options.didStatus ?? 200,
      });
    }
    return new Response(JSON.stringify(records), { status: options.recordsStatus ?? 200 });
  }) as typeof fetch;
  return { doFetch, asked };
}

describe("pullAuditLedger (ADR 0017)", () => {
  it("verifies the served ledger against the served seal and the held seals for this log", async () => {
    const body = await ledger(["a", "b"]);
    const { doFetch, asked } = fakeFetch(body);
    const heldFor: string[] = [];

    const result = await pullAuditLedger({
      auditUrl: AUDIT_URL,
      agentDid: "did:web:x:agents:a",
      fetch: doFetch,
      heldSeals: (log) => {
        heldFor.push(log);
        return [body.seal];
      },
    });

    expect(result).toMatchObject({
      ok: true,
      value: { log: did.id, headSeq: 2, servedSeal: body.seal, newestSeal: { seq: 2 } },
    });
    expect(heldFor).toEqual([did.id]);
    expect(asked[1]).toBe(`${AUDIT_URL}/records?agentId=did%3Aweb%3Ax%3Aagents%3Aa`);
  });

  it("verifies a log with no seal yet", async () => {
    const { entries } = await ledger(["a"]);
    const result = await pullAuditLedger({
      auditUrl: AUDIT_URL,
      fetch: fakeFetch({ entries, seal: null }).doFetch,
    });
    expect(result).toMatchObject({ ok: true, value: { servedSeal: null, unsealedCount: 1 } });
  });

  it("returns the verifier's error for a tampered log", async () => {
    const body = await ledger(["a", "b"]);
    const tampered = { ...body, entries: body.entries.slice(0, 1) };
    const result = await pullAuditLedger({
      auditUrl: AUDIT_URL,
      fetch: fakeFetch(tampered).doFetch,
    });
    expect(result).toEqual({ ok: false, error: { code: "TRUNCATED", sealSeq: 2, headSeq: 1 } });
  });

  it.each([
    ["the DID document is not served", {}, { didStatus: 404 }, /DID document: HTTP 404/],
    ["the records are not served", {}, { recordsStatus: 500 }, /records: HTTP 500/],
    ["the DID document has no key", {}, { didBody: { id: "did:web:x" } }, /no readable key/],
    ["there are no entries", { seal: null }, {}, /no entries/],
    ["the seal is not a string", { entries: [], seal: 5 }, {}, /malformed seal/],
  ])("answers BAD_RESPONSE when %s", async (_name, records, options, reason) => {
    const result = await pullAuditLedger({
      auditUrl: AUDIT_URL,
      fetch: fakeFetch(records, options).doFetch,
    });
    expect(result).toMatchObject({
      ok: false,
      error: { code: "BAD_RESPONSE", reason: expect.stringMatching(reason) },
    });
  });

  it("answers UNREACHABLE when the request fails", async () => {
    const failing = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;
    expect(await pullAuditLedger({ auditUrl: AUDIT_URL, fetch: failing })).toEqual({
      ok: false,
      error: { code: "UNREACHABLE", reason: "ECONNREFUSED" },
    });
  });

  it("reports a non-Error failure as text", async () => {
    const failing = (() => Promise.reject("down")) as typeof fetch;
    expect(await pullAuditLedger({ auditUrl: AUDIT_URL, fetch: failing })).toMatchObject({
      ok: false,
      error: { reason: "down" },
    });
  });
});

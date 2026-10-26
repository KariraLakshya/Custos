import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
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
import { pullAuditLog } from "./audit-log.js";

const AGENT = "did:web:localhost%3A4001:agents:a1";
const OTHER = "did:web:localhost%3A4001:agents:b2";

/** An audit service on `port` serving whatever `state` holds, as the real one would. */
async function fakeAudit(port: number) {
  const keys = generateKeyPair();
  const did = buildDidWebDocument({ domain: `127.0.0.1:${port}`, publicKey: keys.publicKey });
  const state = {
    entries: [] as { seq: number; payload?: string; payloadHash: string; hash: string }[],
    seal: null as string | null,
    lastUrl: "",
  };
  const append = (agentDid: string, action: string) => {
    const payload = serializeAuditRecord({
      agentDid,
      authorityChain: [agentDid],
      tool: "mock-slack",
      action,
      dataCategories: [],
      policy: { rule: "agent-tool-allowlist", decision: "allow" },
      recordedAt: "2026-10-27T10:00:00.000Z",
    });
    const seq = state.entries.length + 1;
    const payloadHash = computeAuditPayloadHash(payload);
    const prevHash = state.entries.at(-1)?.hash ?? AUDIT_GENESIS_HASH;
    state.entries.push({
      seq,
      payload,
      payloadHash,
      hash: computeAuditEntryHash({ seq, prevHash, payloadHash }),
    });
  };
  const seal = async () => {
    const head = state.entries.at(-1)!;
    const issued = await issueAuditSeal({
      seal: { log: did.id, seq: head.seq, headHash: head.hash, sealedAt: "2026-10-27T10:01:00Z" },
      signer: { sign: async (data) => sign(data, keys.secretKey) },
    });
    if (!issued.ok) throw new Error("fixture");
    state.seal = issued.value;
    return issued.value;
  };
  const server: Server = createServer((req, res) => {
    state.lastUrl = req.url ?? "";
    res.setHeader("content-type", "application/json");
    if (req.url?.startsWith("/.well-known/did.json")) {
      res.end(JSON.stringify(did));
      return;
    }
    const agentId = new URL(req.url ?? "/", "http://x").searchParams.get("agentId");
    const entries = state.entries.map(({ seq, payload, payloadHash }) =>
      agentId === null || payload?.includes(agentId)
        ? { seq, payload, payloadHash }
        : { seq, payloadHash },
    );
    res.end(JSON.stringify({ entries, seal: state.seal }));
  });
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  servers.push(server);
  return { url: `http://127.0.0.1:${port}`, did, state, append, seal };
}

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((resolve) => s.close(resolve))));
});

const sealFileIn = async () => join(await mkdtemp(join(tmpdir(), "custos-audit-")), "seal.json");

describe("pullAuditLog (ADR 0017)", () => {
  it("verifies the ledger against its seal, and remembers the seal for next time", async () => {
    const audit = await fakeAudit(4810);
    audit.append(AGENT, "first");
    audit.append(AGENT, "second");
    const seal = await audit.seal();
    const sealFile = await sealFileIn();

    const result = await pullAuditLog({ auditUrl: audit.url, sealFile });

    expect(result).toMatchObject({
      verified: true,
      log: audit.did.id,
      headSeq: 2,
      sealedThrough: 2,
      unsealedCount: 0,
    });
    if (result.verified)
      expect(result.records.map((r) => r.record.action)).toEqual(["first", "second"]);
    expect(JSON.parse(await readFile(sealFile, "utf8"))).toEqual({
      [audit.did.id]: { seq: 2, seal },
    });
  });

  it("asks for one agent and returns only its records, verified against the full chain", async () => {
    const audit = await fakeAudit(4811);
    audit.append(AGENT, "mine");
    audit.append(OTHER, "theirs");
    await audit.seal();

    const result = await pullAuditLog({
      auditUrl: audit.url,
      agentDid: AGENT,
      sealFile: await sealFileIn(),
    });

    expect(audit.state.lastUrl).toBe(`/records?agentId=${encodeURIComponent(AGENT)}`);
    expect(result.verified && result.records.map((r) => r.record.action)).toEqual(["mine"]);
  });

  it("reports TRUNCATED when sealed entries it saw last time are gone, with their seal", async () => {
    const audit = await fakeAudit(4812);
    for (const action of ["a", "b", "c"]) audit.append(AGENT, action);
    await audit.seal();
    const sealFile = await sealFileIn();
    expect((await pullAuditLog({ auditUrl: audit.url, sealFile })).verified).toBe(true);

    audit.state.entries.splice(1);
    audit.state.seal = null;

    expect(await pullAuditLog({ auditUrl: audit.url, sealFile })).toEqual({
      verified: false,
      error: { code: "TRUNCATED", sealSeq: 3, headSeq: 1 },
    });
  });

  it("ignores a remembered seal of another audit log", async () => {
    const first = await fakeAudit(4813);
    first.append(AGENT, "a");
    await first.seal();
    const sealFile = await sealFileIn();
    await pullAuditLog({ auditUrl: first.url, sealFile });

    const second = await fakeAudit(4814);
    second.append(AGENT, "b");
    await second.seal();
    expect((await pullAuditLog({ auditUrl: second.url, sealFile })).verified).toBe(true);
    expect(Object.keys(JSON.parse(await readFile(sealFile, "utf8")) as object)).toHaveLength(2);
  });

  it("never steps back to an older seal than the one it remembers", async () => {
    const audit = await fakeAudit(4815);
    audit.append(AGENT, "a");
    const older = await audit.seal();
    audit.append(AGENT, "b");
    const newer = await audit.seal();
    const sealFile = await sealFileIn();
    await pullAuditLog({ auditUrl: audit.url, sealFile });

    audit.state.seal = older; // the newest seal row deleted; the entries intact
    const result = await pullAuditLog({ auditUrl: audit.url, sealFile });

    expect(result).toMatchObject({ verified: true, sealedThrough: 2 });
    expect(JSON.parse(await readFile(sealFile, "utf8"))).toEqual({
      [audit.did.id]: { seq: 2, seal: newer },
    });
  });

  it("verifies an unsealed log without remembering anything", async () => {
    const audit = await fakeAudit(4816);
    audit.append(AGENT, "a");
    const sealFile = await sealFileIn();
    expect(await pullAuditLog({ auditUrl: audit.url, sealFile })).toMatchObject({
      verified: true,
      sealedThrough: 0,
      unsealedCount: 1,
    });
    await expect(readFile(sealFile, "utf8")).rejects.toThrow(/ENOENT/);
  });

  it("refuses to run on an unreadable seal file rather than forget what it must check", async () => {
    const sealFile = await sealFileIn();
    await writeFile(sealFile, "{not json");
    await expect(pullAuditLog({ auditUrl: "http://127.0.0.1:1", sealFile })).rejects.toThrow(
      /remembered audit seals/,
    );
  });

  it("reports an unreachable service as not verified", async () => {
    const result = await pullAuditLog({
      auditUrl: "http://127.0.0.1:1",
      sealFile: await sealFileIn(),
    });
    expect(result).toMatchObject({ verified: false, error: { code: "UNREACHABLE" } });
  });
});

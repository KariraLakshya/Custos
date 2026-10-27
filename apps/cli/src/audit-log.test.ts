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
  let keys = generateKeyPair();
  let did = buildDidWebDocument({ domain: `127.0.0.1:${port}`, publicKey: keys.publicKey });
  /** A restart on a new key: same address, same log DID, different key. */
  const rotate = () => {
    keys = generateKeyPair();
    did = buildDidWebDocument({ domain: `127.0.0.1:${port}`, publicKey: keys.publicKey });
    return did.verificationMethod[0].publicKeyMultibase;
  };
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
      seal: {
        log: did.id,
        seq: head.seq,
        headHash: head.hash,
        key: did.verificationMethod[0].publicKeyMultibase,
        sealedAt: "2026-10-27T10:01:00Z",
      },
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
  return {
    url: `http://127.0.0.1:${port}`,
    get did() {
      return did;
    },
    state,
    append,
    seal,
    rotate,
  };
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
      [audit.did.id]: { seq: 2, seal, keys: [audit.did.verificationMethod[0].publicKeyMultibase] },
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
      [audit.did.id]: {
        seq: 2,
        seal: newer,
        keys: [audit.did.verificationMethod[0].publicKeyMultibase],
      },
    });
  });

  it("verifies an unsealed log, pinning the key but remembering no seal", async () => {
    const audit = await fakeAudit(4816);
    audit.append(AGENT, "a");
    const sealFile = await sealFileIn();
    expect(await pullAuditLog({ auditUrl: audit.url, sealFile })).toMatchObject({
      verified: true,
      sealedThrough: 0,
      unsealedCount: 1,
    });
    expect(JSON.parse(await readFile(sealFile, "utf8"))).toEqual({
      [audit.did.id]: {
        seq: 0,
        seal: null,
        keys: [audit.did.verificationMethod[0].publicKeyMultibase],
      },
    });
  });

  it("refuses to run on an unreadable seal file rather than forget what it must check", async () => {
    const sealFile = await sealFileIn();
    for (const content of ["{not json", "null", '{"did:web:x":{"seq":1,"seal":null,"keys":[]}}']) {
      await writeFile(sealFile, content);
      await expect(pullAuditLog({ auditUrl: "http://127.0.0.1:1", sealFile })).rejects.toThrow(
        /remembered audit seals/,
      );
    }
    // A file from before keys were pinned (ADR 0017 part 1): a clear way out.
    await writeFile(sealFile, '{"did:web:x":{"seq":1,"seal":"a.b"}}');
    await expect(pullAuditLog({ auditUrl: "http://127.0.0.1:1", sealFile })).rejects.toThrow(
      /did not pin seal keys; remove it/,
    );
  });

  it("reports an unreachable service as not verified", async () => {
    const result = await pullAuditLog({
      auditUrl: "http://127.0.0.1:1",
      sealFile: await sealFileIn(),
    });
    expect(result).toMatchObject({ verified: false, error: { code: "UNREACHABLE" } });
  });

  describe("with an outside seal store (ADR 0017 part 2a)", () => {
    /** A store holding `copies`, recording what it was asked for. */
    function store(copies: () => readonly string[]) {
      const asked: { log: string; fromSeq: number }[] = [];
      return {
        asked,
        list: async (log: string, fromSeq: number) => {
          asked.push({ log, fromSeq });
          return copies();
        },
      };
    }

    it("checks every copy from the start on a first run, and says it did", async () => {
      const audit = await fakeAudit(4817);
      audit.append(AGENT, "a");
      const first = await audit.seal();
      audit.append(AGENT, "b");
      const second = await audit.seal();
      const sealStore = store(() => [first, second]);

      const result = await pullAuditLog({
        auditUrl: audit.url,
        sealFile: await sealFileIn(),
        sealStore,
      });

      expect(sealStore.asked).toEqual([{ log: audit.did.id, fromSeq: 1 }]);
      expect(result).toMatchObject({
        verified: true,
        outsideSealsChecked: true,
        newestOutsideSeal: { seq: 2 },
      });
    });

    it("asks only from the seal it remembered on later runs", async () => {
      const audit = await fakeAudit(4818);
      audit.append(AGENT, "a");
      const first = await audit.seal();
      const sealFile = await sealFileIn();
      await pullAuditLog({ auditUrl: audit.url, sealFile, sealStore: store(() => [first]) });

      audit.append(AGENT, "b");
      const second = await audit.seal();
      const later = store(() => [first, second]);
      await pullAuditLog({ auditUrl: audit.url, sealFile, sealStore: later });

      expect(later.asked).toEqual([{ log: audit.did.id, fromSeq: 1 }]);
      const remembered = JSON.parse(await readFile(sealFile, "utf8")) as Record<
        string,
        { seq: number }
      >;
      expect(remembered[audit.did.id]?.seq).toBe(2);
    });

    it("reports TRUNCATED when the newest entries and the served seal are gone but a copy remains", async () => {
      const audit = await fakeAudit(4819);
      for (const action of ["a", "b", "c"]) audit.append(AGENT, action);
      const copy = await audit.seal();
      audit.state.entries.splice(1);
      audit.state.seal = null;

      const result = await pullAuditLog({
        auditUrl: audit.url,
        sealFile: await sealFileIn(),
        sealStore: store(() => [copy]),
      });

      expect(result).toEqual({
        verified: false,
        error: { code: "TRUNCATED", sealSeq: 3, headSeq: 1 },
      });
    });

    it("fails closed when the store is configured but cannot be read", async () => {
      const audit = await fakeAudit(4820);
      audit.append(AGENT, "a");
      await audit.seal();
      const result = await pullAuditLog({
        auditUrl: audit.url,
        sealFile: await sealFileIn(),
        sealStore: { list: () => Promise.reject(new Error("ECONNREFUSED")) },
      });
      expect(result).toMatchObject({ verified: false, error: { code: "SEAL_STORE_UNREACHABLE" } });
    });

    it("says no outside seals were checked when no store is given", async () => {
      const audit = await fakeAudit(4821);
      audit.append(AGENT, "a");
      await audit.seal();
      expect(
        await pullAuditLog({ auditUrl: audit.url, sealFile: await sealFileIn() }),
      ).toMatchObject({
        verified: true,
        outsideSealsChecked: false,
      });
    });
  });

  // The part 1 bug (found 2026-10-27): every `pnpm demo` run gives the audit
  // service a new key under the same log DID, and a seal remembered under the
  // old key made every later check fail with SEAL_INVALID.
  describe("key rotation (ADR 0017)", () => {
    it("reports KEY_CHANGED, not a broken log, after a restart on a new key, and passes once accepted", async () => {
      const audit = await fakeAudit(4822);
      audit.append(AGENT, "a");
      await audit.seal();
      const sealFile = await sealFileIn();
      expect((await pullAuditLog({ auditUrl: audit.url, sealFile })).verified).toBe(true);
      const firstKey = audit.did.verificationMethod[0].publicKeyMultibase;

      const newKey = audit.rotate();
      audit.append(AGENT, "b");
      await audit.seal();
      const before = await readFile(sealFile, "utf8");

      expect(await pullAuditLog({ auditUrl: audit.url, sealFile })).toEqual({
        verified: false,
        error: { code: "KEY_CHANGED", previous: [firstKey], current: newKey },
      });
      expect(await readFile(sealFile, "utf8")).toBe(before); // nothing remembered

      expect(
        await pullAuditLog({ auditUrl: audit.url, sealFile, acceptKeys: [newKey] }),
      ).toMatchObject({ verified: true, sealedThrough: 2 });
      // Accepted once: the next check passes without the flag.
      expect((await pullAuditLog({ auditUrl: audit.url, sealFile })).verified).toBe(true);
    });
  });

  describe("key rotation, more cases (ADR 0017)", () => {
    it("reports KEY_CHANGED right after a restart, before any new seal, and remembers nothing", async () => {
      const audit = await fakeAudit(4823);
      audit.append(AGENT, "a");
      await audit.seal();
      const sealFile = await sealFileIn();
      await pullAuditLog({ auditUrl: audit.url, sealFile });
      const before = await readFile(sealFile, "utf8");

      const newKey = audit.rotate(); // the restarted service serves its old seal
      expect(await pullAuditLog({ auditUrl: audit.url, sealFile })).toMatchObject({
        verified: false,
        error: { code: "KEY_CHANGED", current: newKey },
      });
      expect(await readFile(sealFile, "utf8")).toBe(before);
    });

    it("still reports a log rewritten under an accepted new key, from the seal kept under the old one", async () => {
      const audit = await fakeAudit(4824);
      for (const action of ["a", "b"]) audit.append(AGENT, action);
      await audit.seal();
      const sealFile = await sealFileIn();
      await pullAuditLog({ auditUrl: audit.url, sealFile });

      // The service's identity rotates the key and rewrites history.
      const newKey = audit.rotate();
      audit.state.entries.splice(0);
      for (const action of ["x", "y", "z"]) audit.append(AGENT, action);
      await audit.seal();

      expect(await pullAuditLog({ auditUrl: audit.url, sealFile, acceptKeys: [newKey] })).toEqual({
        verified: false,
        error: { code: "DIVERGED", seq: 2 },
      });
    });

    it("reports a log rewritten under a new key as DIVERGED, not as a routine key change", async () => {
      const audit = await fakeAudit(4826);
      for (const action of ["a", "b"]) audit.append(AGENT, action);
      await audit.seal();
      const sealFile = await sealFileIn();
      await pullAuditLog({ auditUrl: audit.url, sealFile });

      audit.rotate();
      audit.state.entries.splice(0);
      for (const action of ["x", "y", "z"]) audit.append(AGENT, action);
      await audit.seal();

      // No --accept-key: the first answer must already be the rewrite.
      expect(await pullAuditLog({ auditUrl: audit.url, sealFile })).toEqual({
        verified: false,
        error: { code: "DIVERGED", seq: 2 },
      });
    });

    it("a first-time auditor is told about copies under a key it never trusted, and passes once it accepts it", async () => {
      const audit = await fakeAudit(4825);
      audit.append(AGENT, "a");
      const oldCopy = await audit.seal();
      const oldKey = audit.did.verificationMethod[0].publicKeyMultibase;
      audit.rotate();
      audit.append(AGENT, "b");
      const newCopy = await audit.seal();
      const sealStore = { list: async () => [oldCopy, newCopy] };
      const sealFile = await sealFileIn();

      expect(await pullAuditLog({ auditUrl: audit.url, sealFile, sealStore })).toEqual({
        verified: false,
        error: { code: "SEAL_INVALID", error: { code: "UNTRUSTED_KEY", key: oldKey } },
      });
      expect(
        await pullAuditLog({ auditUrl: audit.url, sealFile, sealStore, acceptKeys: [oldKey] }),
      ).toMatchObject({ verified: true, sealedThrough: 2 });
    });

    it("refuses an --accept-key value that is not an Ed25519 multibase key", async () => {
      await expect(
        pullAuditLog({
          auditUrl: "http://127.0.0.1:1",
          sealFile: await sealFileIn(),
          acceptKeys: ["nope"],
        }),
      ).rejects.toThrow(/not an Ed25519 multibase key/);
    });
  });
});

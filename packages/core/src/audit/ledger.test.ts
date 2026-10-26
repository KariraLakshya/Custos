import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import {
  AUDIT_GENESIS_HASH,
  AUDIT_SEAL_TYPE,
  computeAuditEntryHash,
  computeAuditPayloadHash,
  issueAuditSeal,
  serializeAuditRecord,
  verifyAuditLedger,
  verifyAuditSeal,
  type ServedAuditEntry,
} from "./ledger.js";
import type { AuditRecord } from "./record.js";

const LOG = "did:web:localhost%3A4004";
const AGENT = "did:web:localhost%3A4001:agents:a";
const OTHER = "did:web:localhost%3A4001:agents:b";
const keys = generateKeyPair();
const signer = { sign: async (data: Uint8Array) => sign(data, keys.secretKey) };

function record(n: number, agentDid = AGENT): AuditRecord {
  return {
    agentDid,
    authorityChain: [agentDid],
    tool: "github",
    action: `action-${n}`,
    dataCategories: ["repository-metadata"],
    policy: { rule: "agent-tool-allowlist", decision: "allow" },
    recordedAt: `2026-10-27T10:00:${String(n % 60).padStart(2, "0")}.000Z`,
    reportedBy: { kind: "service", id: "vault-key", name: "vault" },
  };
}

/** Builds a log the way the audit service does: payload stored once, chain from genesis. */
function buildLog(records: readonly AuditRecord[]) {
  const entries: (ServedAuditEntry & { hash: string })[] = [];
  let prevHash = AUDIT_GENESIS_HASH;
  for (const [index, value] of records.entries()) {
    const payload = serializeAuditRecord(value);
    const payloadHash = computeAuditPayloadHash(payload);
    const hash = computeAuditEntryHash({ seq: index + 1, prevHash, payloadHash });
    entries.push({ seq: index + 1, payload, payloadHash, hash });
    prevHash = hash;
  }
  return entries;
}

async function sealAt(
  entries: readonly { seq: number; hash: string }[],
  seq: number,
  options: { log?: string; signWith?: typeof signer } = {},
): Promise<string> {
  const head = entries[seq - 1];
  if (head === undefined) throw new Error("fixture: no entry at seq");
  const issued = await issueAuditSeal({
    seal: { log: options.log ?? LOG, seq, headHash: head.hash, sealedAt: "2026-10-27T10:01:00Z" },
    signer: options.signWith ?? signer,
  });
  if (!issued.ok) throw new Error(issued.error.reason);
  return issued.value;
}

const served = (entries: readonly (ServedAuditEntry & { hash?: string })[]) =>
  entries.map(({ seq, payload, payloadHash }) => ({
    seq,
    payloadHash,
    ...(payload === undefined ? {} : { payload }),
  }));

const verifyLog = (entries: readonly unknown[], seals: readonly string[] = []) =>
  verifyAuditLedger({ entries, seals, publicKey: keys.publicKey, log: LOG });

describe("computeAuditEntryHash", () => {
  it("is SHA-256 over the domain tag, seq, previous hash and payload hash", () => {
    const payloadHash = "ab".repeat(32);
    const input = Buffer.concat([
      Buffer.from("custos.audit.entry.v1\u0000"),
      Buffer.from([0, 0, 0, 0, 0, 0, 0, 7]),
      Buffer.from(AUDIT_GENESIS_HASH, "hex"),
      Buffer.from(payloadHash, "hex"),
    ]);
    expect(computeAuditEntryHash({ seq: 7, prevHash: AUDIT_GENESIS_HASH, payloadHash })).toBe(
      Buffer.from(sha256(input)).toString("hex"),
    );
  });

  it("binds the position: the same payload at another seq or after another entry hashes differently", () => {
    const payloadHash = "ab".repeat(32);
    const base = computeAuditEntryHash({ seq: 1, prevHash: AUDIT_GENESIS_HASH, payloadHash });
    expect(computeAuditEntryHash({ seq: 2, prevHash: AUDIT_GENESIS_HASH, payloadHash })).not.toBe(
      base,
    );
    expect(computeAuditEntryHash({ seq: 1, prevHash: "cd".repeat(32), payloadHash })).not.toBe(
      base,
    );
  });

  it.each([
    ["a zero seq", { seq: 0 }],
    ["a fractional seq", { seq: 1.5 }],
    ["a short previous hash", { prevHash: "ab" }],
    ["an uppercase payload hash", { payloadHash: "AB".repeat(32) }],
  ])("refuses %s", (_name, override) => {
    expect(() =>
      computeAuditEntryHash({
        seq: 1,
        prevHash: AUDIT_GENESIS_HASH,
        payloadHash: "ab".repeat(32),
        ...override,
      }),
    ).toThrow();
  });
});

describe("issueAuditSeal and verifyAuditSeal", () => {
  it("round-trips a seal that names its log and type", async () => {
    const log = buildLog([record(1)]);
    const verified = verifyAuditSeal({
      seal: await sealAt(log, 1),
      publicKey: keys.publicKey,
      log: LOG,
    });
    expect(verified).toMatchObject({
      ok: true,
      value: { typ: AUDIT_SEAL_TYPE, log: LOG, seq: 1, headHash: log[0]!.hash },
    });
  });

  it("fails closed when the signer throws", async () => {
    const issued = await issueAuditSeal({
      seal: { log: LOG, seq: 1, headHash: AUDIT_GENESIS_HASH, sealedAt: "x" },
      signer: {
        sign: async () => {
          throw new Error("ThrottlingException");
        },
      },
    });
    expect(issued).toEqual({
      ok: false,
      error: { code: "SIGNING_FAILED", reason: "ThrottlingException" },
    });
  });

  it("reports a non-Error throw as text", async () => {
    const issued = await issueAuditSeal({
      seal: { log: LOG, seq: 1, headHash: AUDIT_GENESIS_HASH, sealedAt: "x" },
      signer: { sign: () => Promise.reject("down") },
    });
    expect(issued).toMatchObject({ ok: false, error: { reason: "down" } });
  });

  it("refuses a seal signed by another key", async () => {
    const log = buildLog([record(1)]);
    const other = generateKeyPair();
    const seal = await sealAt(log, 1, {
      signWith: { sign: async (data) => sign(data, other.secretKey) },
    });
    expect(verifyAuditSeal({ seal, publicKey: keys.publicKey, log: LOG })).toEqual({
      ok: false,
      error: { code: "SIGNATURE_INVALID" },
    });
  });

  it("refuses a genuine seal of another log", async () => {
    const log = buildLog([record(1)]);
    const seal = await sealAt(log, 1, { log: "did:web:other.example" });
    expect(verifyAuditSeal({ seal, publicKey: keys.publicKey, log: LOG })).toEqual({
      ok: false,
      error: { code: "WRONG_LOG" },
    });
  });

  it("refuses a seal whose claims were edited after signing", async () => {
    const log = buildLog([record(1), record(2)]);
    const [encoded, signature] = (await sealAt(log, 1)).split(".") as [string, string];
    const claims = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as object;
    const edited = Buffer.from(JSON.stringify({ ...claims, seq: 2, headHash: log[1]!.hash }));
    expect(
      verifyAuditSeal({
        seal: `${edited.toString("base64url")}.${signature}`,
        publicKey: keys.publicKey,
        log: LOG,
      }),
    ).toEqual({ ok: false, error: { code: "SIGNATURE_INVALID" } });
  });

  async function signedClaims(claims: unknown): Promise<string> {
    const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const signature = await signer.sign(Buffer.from(encoded, "utf8"));
    return `${encoded}.${Buffer.from(signature).toString("base64url")}`;
  }

  it.each([
    ["no separator", async () => "abc"],
    ["two separators", async () => "a.b.c"],
    ["a body that is not JSON", async () => `${Buffer.from("{").toString("base64url")}.sig`],
    [
      "another type",
      () => signedClaims({ typ: "x", log: LOG, seq: 1, headHash: "ab".repeat(32), sealedAt: "t" }),
    ],
    [
      "no log",
      () =>
        signedClaims({ typ: AUDIT_SEAL_TYPE, seq: 1, headHash: "ab".repeat(32), sealedAt: "t" }),
    ],
    [
      "a zero seq",
      () =>
        signedClaims({
          typ: AUDIT_SEAL_TYPE,
          log: LOG,
          seq: 0,
          headHash: "ab".repeat(32),
          sealedAt: "t",
        }),
    ],
    [
      "a short head hash",
      () => signedClaims({ typ: AUDIT_SEAL_TYPE, log: LOG, seq: 1, headHash: "ab", sealedAt: "t" }),
    ],
    [
      "no time",
      () => signedClaims({ typ: AUDIT_SEAL_TYPE, log: LOG, seq: 1, headHash: "ab".repeat(32) }),
    ],
    ["a null body", () => signedClaims(null)],
  ])("refuses a malformed seal: %s", async (_name, make) => {
    const result = verifyAuditSeal({ seal: await make(), publicKey: keys.publicKey, log: LOG });
    expect(result).toMatchObject({ ok: false, error: { code: "MALFORMED_SEAL" } });
  });
});

describe("verifyAuditLedger", () => {
  it("accepts an untouched log and its seal, returning every record in order", async () => {
    const log = buildLog([record(1), record(2), record(3)]);
    const result = verifyLog(served(log), [await sealAt(log, 3)]);
    expect(result).toMatchObject({ ok: true, value: { headSeq: 3, unsealedCount: 0 } });
    if (!result.ok) return;
    expect(result.value.records.map((r) => r.record.action)).toEqual([
      "action-1",
      "action-2",
      "action-3",
    ]);
    expect(result.value.newestSeal?.seq).toBe(3);
  });

  it("accepts an empty log with no seal", () => {
    expect(verifyLog([])).toEqual({
      ok: true,
      value: { records: [], headSeq: 0, unsealedCount: 0 },
    });
  });

  it("counts entries after the newest seal as not sealed yet", async () => {
    const log = buildLog([record(1), record(2), record(3)]);
    const result = verifyLog(served(log), [await sealAt(log, 1)]);
    expect(result).toMatchObject({ ok: true, value: { unsealedCount: 2 } });
  });

  it("checks one agent's entries while others are served as hashes only", async () => {
    const log = buildLog([record(1), record(2, OTHER), record(3)]);
    const view = served(log).map((entry, index) =>
      index === 1 ? { seq: entry.seq, payloadHash: entry.payloadHash } : entry,
    );
    const result = verifyLog(view, [await sealAt(log, 3)]);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.records.map((r) => r.seq)).toEqual([1, 3]);
  });

  it("keeps the newest of several matching seals, in any order", async () => {
    const log = buildLog([record(1), record(2), record(3)]);
    const result = verifyLog(served(log), [await sealAt(log, 3), await sealAt(log, 2)]);
    expect(result).toMatchObject({ ok: true, value: { newestSeal: { seq: 3 } } });
  });

  describe("detects tampering", () => {
    it("an edited entry", async () => {
      const log = served(buildLog([record(1), record(2)]));
      const edited = log.map((entry, index) =>
        index === 0
          ? { ...entry, payload: serializeAuditRecord({ ...record(1), action: "nothing" }) }
          : entry,
      );
      expect(verifyLog(edited)).toEqual({ ok: false, error: { code: "PAYLOAD_MISMATCH", seq: 1 } });
    });

    it("an edited entry whose hash was recomputed too, against a seal", async () => {
      const log = buildLog([record(1), record(2)]);
      const seal = await sealAt(log, 2);
      const payload = serializeAuditRecord({ ...record(1), action: "nothing" });
      const edited = served(log).map((entry, index) =>
        index === 0 ? { ...entry, payload, payloadHash: computeAuditPayloadHash(payload) } : entry,
      );
      expect(verifyLog(edited, [seal])).toEqual({
        ok: false,
        error: { code: "DIVERGED", seq: 2 },
      });
    });

    it("a deleted middle entry", () => {
      const log = served(buildLog([record(1), record(2), record(3)]));
      expect(verifyLog([log[0], log[2]])).toEqual({
        ok: false,
        error: { code: "SEQUENCE_GAP", expected: 2, found: 3 },
      });
    });

    it("a deleted middle entry with the rest renumbered, against a seal", async () => {
      const log = buildLog([record(1), record(2), record(3)]);
      const seal = await sealAt(log, 3);
      const renumbered = [served(log)[0]!, { ...served(log)[2]!, seq: 2 }];
      expect(verifyLog(renumbered, [seal])).toEqual({
        ok: false,
        error: { code: "TRUNCATED", sealSeq: 3, headSeq: 2 },
      });
    });

    it("two entries swapped", async () => {
      const log = buildLog([record(1), record(2)]);
      const seal = await sealAt(log, 2);
      const [first, second] = served(log) as [ServedAuditEntry, ServedAuditEntry];
      const swapped = [
        { ...second, seq: 1 },
        { ...first, seq: 2 },
      ];
      expect(verifyLog(swapped, [seal])).toEqual({
        ok: false,
        error: { code: "DIVERGED", seq: 2 },
      });
    });

    it("the newest sealed entries deleted, against a seal the verifier already holds", async () => {
      const log = buildLog([record(1), record(2), record(3)]);
      const remembered = await sealAt(log, 3);
      expect(verifyLog(served(log).slice(0, 1), [remembered])).toEqual({
        ok: false,
        error: { code: "TRUNCATED", sealSeq: 3, headSeq: 1 },
      });
    });

    it("a log rebuilt and re-sealed with the same key, against a seal the verifier already holds", async () => {
      const original = buildLog([record(1), record(2)]);
      const remembered = await sealAt(original, 2);
      const rebuilt = buildLog([
        record(1),
        { ...record(2), policy: { rule: "x", decision: "deny" } },
      ]);
      const freshSeal = await sealAt(rebuilt, 2);
      expect(verifyLog(served(rebuilt), [freshSeal])).toMatchObject({ ok: true });
      expect(verifyLog(served(rebuilt), [freshSeal, remembered])).toEqual({
        ok: false,
        error: { code: "DIVERGED", seq: 2 },
      });
    });

    it("a seal signed by another key", async () => {
      const log = buildLog([record(1)]);
      const other = generateKeyPair();
      const forged = await sealAt(log, 1, {
        signWith: { sign: async (data) => sign(data, other.secretKey) },
      });
      expect(verifyLog(served(log), [forged])).toEqual({
        ok: false,
        error: { code: "SEAL_INVALID", error: { code: "SIGNATURE_INVALID" } },
      });
    });
  });

  describe("refuses malformed input", () => {
    const good = served(buildLog([record(1)]))[0]!;
    it.each([
      ["a non-object", "x", "not an object"],
      ["null", null, "not an object"],
      ["a zero seq", { ...good, seq: 0 }, "seq"],
      ["a string seq", { ...good, seq: "1" }, "seq"],
      ["a short payload hash", { ...good, payloadHash: "ab" }, "payloadHash"],
      ["a numeric payload", { ...good, payload: 5 }, "payload"],
    ])("%s", (_name, entry, reason) => {
      expect(verifyLog([entry])).toMatchObject({
        ok: false,
        error: { code: "MALFORMED_ENTRY", index: 0, reason: expect.stringContaining(reason) },
      });
    });

    it("a payload that is not JSON", () => {
      const payload = "{not json";
      expect(
        verifyLog([{ seq: 1, payload, payloadHash: computeAuditPayloadHash(payload) }]),
      ).toEqual({ ok: false, error: { code: "MALFORMED_RECORD", seq: 1 } });
    });

    it("a payload that is JSON but not a record", () => {
      const payload = JSON.stringify({ action: "x" });
      expect(
        verifyLog([{ seq: 1, payload, payloadHash: computeAuditPayloadHash(payload) }]),
      ).toEqual({ ok: false, error: { code: "MALFORMED_RECORD", seq: 1 } });
    });

    it("a record with a malformed reporter", () => {
      const payload = JSON.stringify({
        ...record(1),
        reportedBy: { kind: "robot", id: "x", name: "y" },
      });
      expect(
        verifyLog([{ seq: 1, payload, payloadHash: computeAuditPayloadHash(payload) }]),
      ).toEqual({ ok: false, error: { code: "MALFORMED_RECORD", seq: 1 } });
    });

    it("a log that does not start at 1", () => {
      expect(verifyLog([{ ...good, seq: 2 }])).toEqual({
        ok: false,
        error: { code: "SEQUENCE_GAP", expected: 1, found: 2 },
      });
    });
  });
});

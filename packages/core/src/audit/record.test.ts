import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import { issueAuditRecord, verifyAuditRecord, type AuditRecord } from "./record.js";

const AGENT_DID = "did:web:localhost%3A4001:agents:0f8f6a1e-9c2b-4a3d-8f1e-1b2c3d4e5f60";

function signerFor(secretKey: Uint8Array) {
  return { sign: async (data: Uint8Array) => sign(data, secretKey) };
}

function recordFor(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    agentDid: AGENT_DID,
    authorityChain: [AGENT_DID],
    tool: "github",
    action: "list-repos",
    dataCategories: ["repository-metadata"],
    policy: { rule: "agent-tool-allowlist", decision: "allow" },
    recordedAt: "2026-09-12T10:00:00.000Z",
    ...overrides,
  };
}

/** Encodes arbitrary claims and signs them, to exercise the verify path. */
async function signRaw(claims: unknown, secretKey: Uint8Array): Promise<string> {
  const encodedRecord = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const signature = sign(Buffer.from(encodedRecord, "utf8"), secretKey);
  return `${encodedRecord}.${Buffer.from(signature).toString("base64url")}`;
}

describe("issueAuditRecord", () => {
  it("produces a two-part compact envelope", async () => {
    const { secretKey } = generateKeyPair();
    const issued = await issueAuditRecord({ record: recordFor(), signer: signerFor(secretKey) });
    expect(issued.ok).toBe(true);
    if (issued.ok) expect(issued.value.split(".")).toHaveLength(2);
  });

  it("fails closed when the signer throws rather than propagating", async () => {
    const issued = await issueAuditRecord({
      record: recordFor(),
      signer: {
        sign: async () => {
          throw new Error("KMS unavailable");
        },
      },
    });
    expect(issued.ok).toBe(false);
    if (!issued.ok) {
      expect(issued.error.code).toBe("SIGNING_FAILED");
      expect(issued.error.reason).toContain("KMS unavailable");
    }
  });

  it("reports a non-Error thrown by the signer without crashing", async () => {
    const issued = await issueAuditRecord({
      record: recordFor(),
      signer: {
        sign: async () => {
          throw "kms offline";
        },
      },
    });
    expect(issued.ok).toBe(false);
    if (!issued.ok) expect(issued.error.reason).toBe("kms offline");
  });
});

describe("verifyAuditRecord", () => {
  it("verifies a record and returns its fields", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const record = recordFor({ reason: "within granted policy" });
    const issued = await issueAuditRecord({ record, signer: signerFor(secretKey) });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const verified = verifyAuditRecord({ record: issued.value, publicKey });
    expect(verified.ok).toBe(true);
    if (verified.ok) expect(verified.value).toEqual(record);
  });

  it("verifies a denied action record", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const record = recordFor({
      tool: "stripe",
      policy: { rule: "agent-tool-allowlist", decision: "deny" },
      reason: "no policy grant for this agent/tool pair",
    });
    const issued = await issueAuditRecord({ record, signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    const verified = verifyAuditRecord({ record: issued.value, publicKey });
    expect(verified.ok).toBe(true);
    if (verified.ok) expect(verified.value.policy.decision).toBe("deny");
  });

  // An audit record is a permanent statement about what already happened —
  // it must keep verifying on replay, unlike a scoped token.
  it("keeps verifying on replay — a record never expires", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const issued = await issueAuditRecord({ record: recordFor(), signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    expect(verifyAuditRecord({ record: issued.value, publicKey }).ok).toBe(true);
    expect(verifyAuditRecord({ record: issued.value, publicKey }).ok).toBe(true);
  });

  it("rejects a record whose fields were tampered with after signing", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const issued = await issueAuditRecord({ record: recordFor(), signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");

    const [, signature] = issued.value.split(".") as [string, string];
    const swapped = Buffer.from(
      JSON.stringify(
        recordFor({ policy: { rule: "agent-tool-allowlist", decision: "allow" }, tool: "stripe" }),
      ),
      "utf8",
    ).toString("base64url");
    const result = verifyAuditRecord({ record: `${swapped}.${signature}`, publicKey });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("SIGNATURE_INVALID");
  });

  it("rejects a record signed by an unknown key", async () => {
    const { secretKey } = generateKeyPair();
    const impostor = generateKeyPair();
    const issued = await issueAuditRecord({ record: recordFor(), signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");

    const result = verifyAuditRecord({ record: issued.value, publicKey: impostor.publicKey });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("SIGNATURE_INVALID");
  });

  it.each([
    ["no separator", "not-a-record"],
    ["too many separators", "a.b.c"],
    ["empty string", ""],
  ])("rejects a malformed envelope (%s)", (_label, record) => {
    const { publicKey } = generateKeyPair();
    const result = verifyAuditRecord({ record, publicKey });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("MALFORMED_RECORD");
  });

  it("rejects claims that are not JSON", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const encodedRecord = Buffer.from("this is not json", "utf8").toString("base64url");
    const signature = sign(Buffer.from(encodedRecord, "utf8"), secretKey);
    const result = verifyAuditRecord({
      record: `${encodedRecord}.${Buffer.from(signature).toString("base64url")}`,
      publicKey,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("MALFORMED_RECORD");
  });

  // Each of these is a correctly signed envelope carrying fields that are
  // structurally wrong — proving validation is not skipped once the
  // signature checks out.
  it.each([
    ["no actor: neither agentDid nor principal", { ...recordFor(), agentDid: undefined }],
    ["empty agentDid", { ...recordFor(), agentDid: "" }],
    ["missing authorityChain", { ...recordFor(), authorityChain: undefined }],
    ["non-array authorityChain", { ...recordFor(), authorityChain: AGENT_DID }],
    ["non-string authorityChain entry", { ...recordFor(), authorityChain: [1] }],
    ["empty tool", { ...recordFor(), tool: "" }],
    ["missing action", { ...recordFor(), action: undefined }],
    ["empty action", { ...recordFor(), action: "" }],
    ["missing dataCategories", { ...recordFor(), dataCategories: undefined }],
    ["non-array dataCategories", { ...recordFor(), dataCategories: "repository-metadata" }],
    ["missing recordedAt", { ...recordFor(), recordedAt: undefined }],
    ["non-string reason", { ...recordFor(), reason: 7 }],
    ["missing policy", { ...recordFor(), policy: undefined }],
    ["non-object policy", { ...recordFor(), policy: "allow" }],
    ["missing policy.rule", { ...recordFor(), policy: { decision: "allow" } }],
    ["invalid policy.decision", { ...recordFor(), policy: { rule: "x", decision: "maybe" } }],
    ["non-object principal", { ...recordFor(), principal: "lakshya" }],
    [
      "unknown principal kind",
      { ...recordFor(), principal: { kind: "agent", id: "a", name: "b" } },
    ],
    ["principal without id", { ...recordFor(), principal: { kind: "operator", name: "b" } }],
    [
      "principal with empty name",
      { ...recordFor(), principal: { kind: "operator", id: "a", name: "" } },
    ],
    ["null claims", null],
    ["array claims", []],
    ["string claims", "audited"],
  ])("rejects correctly signed but structurally invalid claims (%s)", async (_label, claims) => {
    const { publicKey, secretKey } = generateKeyPair();
    const record = await signRaw(claims, secretKey);
    const result = verifyAuditRecord({ record, publicKey });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("MALFORMED_RECORD");
  });

  it("verifies a control-plane record: a principal, no agent, an empty authority chain", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const record: AuditRecord = {
      principal: { kind: "operator", id: "0123456789abcdef", name: "lakshya" },
      authorityChain: [],
      tool: "stripe",
      action: "credentials.store",
      dataCategories: [],
      policy: { rule: "control-plane-scope:credentials:write", decision: "allow" },
      recordedAt: "2026-10-02T10:00:00.000Z",
    };
    const issued = await issueAuditRecord({ record, signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    const result = verifyAuditRecord({ record: issued.value, publicKey });
    expect(result).toEqual({ ok: true, value: record });
  });

  it("verifies a control-plane record about an agent, with no tool", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const record: AuditRecord = {
      agentDid: AGENT_DID,
      principal: { kind: "operator", id: "0123456789abcdef", name: "lakshya" },
      authorityChain: [],
      action: "agents.revoke",
      dataCategories: [],
      policy: { rule: "control-plane-scope:agents:revoke", decision: "allow" },
      recordedAt: "2026-10-02T10:00:00.000Z",
    };
    const issued = await issueAuditRecord({ record, signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    expect(verifyAuditRecord({ record: issued.value, publicKey })).toEqual({
      ok: true,
      value: record,
    });
  });

  it("rejects a tampered principal", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const record = recordFor({
      principal: { kind: "operator", id: "0123456789abcdef", name: "lakshya" },
      authorityChain: [],
    });
    const issued = await issueAuditRecord({ record, signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    const [, signature] = issued.value.split(".") as [string, string];
    const forged = { ...record, principal: { ...record.principal!, name: "someone-else" } };
    const encoded = Buffer.from(JSON.stringify(forged), "utf8").toString("base64url");
    const result = verifyAuditRecord({ record: `${encoded}.${signature}`, publicKey });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("SIGNATURE_INVALID");
  });

  it("fails closed on a malformed public key instead of throwing", async () => {
    const { secretKey } = generateKeyPair();
    const issued = await issueAuditRecord({ record: recordFor(), signer: signerFor(secretKey) });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    const result = verifyAuditRecord({ record: issued.value, publicKey: new Uint8Array(5) });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("SIGNATURE_INVALID");
  });
});

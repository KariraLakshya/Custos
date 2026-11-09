import { describe, expect, it, vi } from "vitest";
import {
  buildHandOff,
  buildStatusListEntry,
  generateKeyPair,
  handOffHash,
  issueCredential,
  pinnedDidDocument,
  publicKeyToMultibase,
  sign,
  type AuditRecord,
  type SignedCredential,
} from "@custos/core";
import { checkDelegations, resolvePinnedIssuer } from "./delegation-audit.js";

const ISSUER = "did:web:localhost%3A4001";
const issuerKeys = generateKeyPair();
const document = pinnedDidDocument(ISSUER, issuerKeys.publicKey);
const CHECKED_AT = new Date("2026-11-09T10:00:00.000Z");
const RECORDED_AT = "2026-11-09T10:00:00.250Z";
const TOOL = "mock-database";
const ACTION = "query";

interface Agent {
  readonly did: string;
  readonly keys: ReturnType<typeof generateKeyPair>;
  readonly credential: SignedCredential;
}

async function agent(signWith = issuerKeys): Promise<Agent> {
  const keys = generateKeyPair();
  const did = `${ISSUER}:agents:${crypto.randomUUID()}`;
  const issued = await issueCredential({
    unsignedCredential: {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {
          publicKeyMultibase: {
            "@id": "https://w3id.org/security#publicKeyMultibase",
            "@type": "https://w3id.org/security#multibase",
          },
        },
      ],
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: ["VerifiableCredential"],
      issuer: ISSUER,
      validFrom: new Date(CHECKED_AT.getTime() - 60_000).toISOString(),
      credentialSubject: { id: did, publicKeyMultibase: publicKeyToMultibase(keys.publicKey) },
      credentialStatus: buildStatusListEntry({
        statusListCredential: "http://localhost:4003/status/revocation",
        statusListIndex: 3,
      }),
    },
    signer: {
      id: `${ISSUER}#${publicKeyToMultibase(signWith.publicKey)}`,
      sign: ({ data }) => Promise.resolve(sign(data, signWith.secretKey)),
    },
  });
  if (!issued.ok) throw new Error(issued.error.reason);
  return { did, keys, credential: issued.value };
}

const [a, b] = await Promise.all([agent(), agent()]);
const handOff = buildHandOff({
  from: a.did,
  to: b.did,
  grants: [{ tool: TOOL, actions: [ACTION] }],
  depth: 0,
  now: CHECKED_AT,
  ttlSeconds: 600,
  secretKey: a.keys.secretKey,
});
const REF = handOffHash(handOff);

function callRecord(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    agentDid: b.did,
    authorityChain: [a.did, b.did],
    tool: TOOL,
    action: ACTION,
    dataCategories: [],
    policy: { rule: `delegation:${TOOL}`, decision: "allow" },
    recordedAt: RECORDED_AT,
    delegationRef: REF,
    ...overrides,
  };
}

function issuedRecord(
  overrides: Partial<AuditRecord> = {},
  evidence: Partial<NonNullable<AuditRecord["delegation"]>> = {},
): AuditRecord {
  return callRecord({
    reason: "token issued under delegation",
    delegation: {
      root: { kind: "operator", id: "0123456789abcdef", name: "lakshya", via: "sso" },
      handOffs: [handOff],
      credentials: [a.credential],
      checkedAt: CHECKED_AT.toISOString(),
      ...evidence,
    },
    ...overrides,
  });
}

const plain: AuditRecord = {
  agentDid: b.did,
  authorityChain: [b.did],
  tool: TOOL,
  action: ACTION,
  dataCategories: [],
  policy: { rule: "scoped-token", decision: "allow" },
  recordedAt: RECORDED_AT,
};

function check(records: AuditRecord[], resolveIssuer = () => Promise.resolve(document)) {
  return checkDelegations({
    records: records.map((record, i) => ({ seq: i + 1, record })),
    issuerDid: ISSUER,
    resolveIssuer,
  });
}

describe("checkDelegations (ADR 0020 §6)", () => {
  it("re-verifies an issuance entry and links each call to it, printing operator → A → B", async () => {
    const result = await check([issuedRecord(), callRecord(), plain]);
    const chain = `lakshya (operator, sso) → ${a.did} → ${b.did}`;
    expect(result).toEqual({
      ok: true,
      checked: [
        { seq: 1, kind: "issued", chain },
        { seq: 2, kind: "call", chain },
      ],
    });
  });

  it("links each call to its own token's issuance when one hand-off covers two actions", async () => {
    const both = buildHandOff({
      from: a.did,
      to: b.did,
      grants: [{ tool: TOOL, actions: [ACTION, "write"] }],
      depth: 0,
      now: CHECKED_AT,
      ttlSeconds: 600,
      secretKey: a.keys.secretKey,
    });
    const delegationRef = handOffHash(both);
    const records = [
      issuedRecord({ delegationRef }, { handOffs: [both] }),
      issuedRecord({ delegationRef, action: "write" }, { handOffs: [both] }),
      callRecord({ delegationRef }),
      callRecord({ delegationRef, action: "write" }),
    ];
    const result = await check(records);
    expect(result.ok && result.checked.map((c) => c.kind)).toEqual([
      "issued",
      "issued",
      "call",
      "call",
    ]);
  });

  it("links a call recorded before its issuance entry (both reports are fire-and-forget)", async () => {
    const result = await check([callRecord(), issuedRecord()]);
    expect(result.ok && result.checked.map((c) => c.kind)).toEqual(["call", "issued"]);
  });

  it("checks the chain at the vault's time of the check, not today's", async () => {
    // The hand-off lived 10 minutes in 2026; it is long expired by now.
    expect((await check([issuedRecord()])).ok).toBe(true);
  });

  it("prints a root with no `via` without one", async () => {
    const root = { kind: "operator", id: "0123456789abcdef", name: "ops-key" } as const;
    const result = await check([issuedRecord({}, { root })]);
    expect(result.ok && result.checked[0]?.chain).toBe(`ops-key (operator) → ${a.did} → ${b.did}`);
  });

  it("does not resolve the issuer when there is no delegated entry", async () => {
    const resolve = vi.fn(() => Promise.resolve(document));
    expect(await check([plain], resolve)).toEqual({ ok: true, checked: [] });
    expect(resolve).not.toHaveBeenCalled();
  });

  it("fails, not passes, when the pinned issuer cannot be resolved", async () => {
    const result = await check([issuedRecord()], () => Promise.reject(new Error("down")));
    expect(result).toEqual({
      ok: false,
      error: { code: "DELEGATION_UNCHECKABLE", reason: "down" },
    });
  });

  it("fails on a non-Error rejection too, with its text", async () => {
    const result = await check([issuedRecord()], () => Promise.reject("plain"));
    expect(result).toEqual({
      ok: false,
      error: { code: "DELEGATION_UNCHECKABLE", reason: "plain" },
    });
  });

  const tampered = (h: string) => {
    const [claims, signature] = h.split(".");
    const parsed = JSON.parse(Buffer.from(claims!, "base64url").toString("utf8")) as {
      grants: unknown;
    };
    parsed.grants = [{ tool: TOOL, actions: [ACTION, "write"] }];
    return `${Buffer.from(JSON.stringify(parsed)).toString("base64url")}.${signature}`;
  };

  it.each([
    [
      "a forged hand-off",
      () => issuedRecord({}, { handOffs: [tampered(handOff)] }),
      "SIGNATURE_INVALID",
    ],
    ["an action the chain does not cover", () => issuedRecord({ action: "write" }), "NOT_COVERED"],
    [
      "a different requester",
      () => issuedRecord({ agentDid: a.did, authorityChain: [b.did, a.did] }),
      "WRONG_HOLDER",
    ],
    [
      "a delegator credential the pinned issuer did not sign",
      async () => issuedRecord({}, { credentials: [(await agent(generateKeyPair())).credential] }),
      "CREDENTIAL_INVALID",
    ],
    [
      "a chain checked after its hand-off expired",
      () =>
        issuedRecord(
          { recordedAt: "2026-11-09T11:00:00.000Z" },
          { checkedAt: "2026-11-09T11:00:00.000Z" },
        ),
      "EXPIRED",
    ],
    [
      "an authority chain other than the one proven",
      () => issuedRecord({ authorityChain: [`${ISSUER}:agents:someone-else`, b.did] }),
      "the entry's authority chain is not the chain its evidence proves",
    ],
    [
      "a reference other than the evidence's",
      () => issuedRecord({ delegationRef: "not-the-hash" }),
      "the entry's reference is not its evidence's",
    ],
    [
      "a check timed after the entry was recorded",
      () => issuedRecord({}, { checkedAt: "2026-11-09T10:05:01.000Z" }),
      "checked after it was recorded",
    ],
    [
      "a check backdated well before the entry was recorded",
      () => issuedRecord({ recordedAt: "2026-11-09T11:00:00.000Z" }),
      "checked long before it was recorded",
    ],
    ["an unreadable time", () => issuedRecord({}, { checkedAt: "soon" }), "unreadable time"],
    ["an unreadable recorded time", () => issuedRecord({ recordedAt: "later" }), "unreadable time"],
    [
      "no tool",
      () => issuedRecord({ tool: undefined }),
      "a delegated entry must name its agent and tool",
    ],
  ])("fails on %s", async (_label, make, reason) => {
    const result = await check([await make()]);
    expect(result).toEqual({
      ok: false,
      error: { code: "DELEGATION_INVALID", seq: 1, reason },
    });
  });

  it.each([
    ["a call with no issuance entry", [callRecord()]],
    ["a call naming another reference", [issuedRecord(), callRecord({ delegationRef: "other" })]],
    ["a call for another action", [issuedRecord(), callRecord({ action: "write" })]],
    ["a call for another tool", [issuedRecord(), callRecord({ tool: "other-tool" })]],
    ["a call by another agent", [issuedRecord(), callRecord({ agentDid: a.did })]],
    [
      "a call naming another chain",
      [issuedRecord(), callRecord({ authorityChain: [a.did, a.did, b.did] })],
    ],
    [
      "a chain with no reference at all",
      [issuedRecord(), callRecord({ delegationRef: undefined })],
    ],
  ])("fails as unlinked on %s", async (_label, records) => {
    const result = await check(records);
    expect(result).toEqual({
      ok: false,
      error: { code: "DELEGATION_UNLINKED", seq: records.length },
    });
  });
});

describe("resolvePinnedIssuer", () => {
  const respond = (status: number, body: unknown) =>
    vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status })));

  it("returns the pinned DID's document from its did:web address", async () => {
    const fetchImpl = respond(200, document);
    expect(await resolvePinnedIssuer(ISSUER, fetchImpl)).toEqual(document);
    expect(fetchImpl).toHaveBeenCalledWith(
      "http://localhost:4001/.well-known/did.json",
      expect.anything(),
    );
  });

  it("refuses a document for another DID, so a server cannot swap the issuer", async () => {
    await expect(
      resolvePinnedIssuer(ISSUER, respond(200, { ...document, id: "did:web:evil.example" })),
    ).rejects.toThrow(/expected did:web:localhost%3A4001/);
  });

  it("refuses an HTTP error and a null body", async () => {
    await expect(resolvePinnedIssuer(ISSUER, respond(503, {}))).rejects.toThrow(/HTTP 503/);
    await expect(resolvePinnedIssuer(ISSUER, respond(200, null))).rejects.toThrow(/undefined/);
  });
});

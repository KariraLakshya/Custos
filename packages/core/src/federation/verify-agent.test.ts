import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../crypto/ed25519.js";
import { publicKeyToMultibase } from "../did/did-web.js";
import { buildTokenRequestProof } from "../proof/possession.js";
import type { SignedCredential } from "../vc/credential.js";
import {
  issueAgent,
  issueCustomAgent,
  expiringReplayGuard,
  issueList,
  makeOrganisation,
  memoryReplayGuard,
  NOW,
  proofFor,
  RECEIVER,
  REQUEST,
  STATUS_LIST_ID,
  type Agent,
  type Organisation,
  type Draft,
  sub,
  stat,
} from "./fixtures.js";
import { verifyForeignStatusList, type VerifiedForeignStatusList } from "./status-view.js";
import type { TrustAnchor } from "./trust-anchor.js";
import { verifyForeignAgent, type ForeignReplayGuard } from "./verify-agent.js";

const PROOF_SKEW = 30;
const CLOCK_SKEW = 5;

async function viewOf(
  org: Organisation,
  options: Parameters<typeof issueList>[1] = {},
  now = NOW,
): Promise<VerifiedForeignStatusList> {
  const result = await verifyForeignStatusList({
    credential: await issueList(org, options),
    anchor: org.anchor,
    now,
    maxClockSkewSeconds: CLOCK_SKEW,
  });
  if (!result.ok) throw new Error(`fixture list rejected: ${result.error.code}`);
  return result.value;
}

interface Call {
  credential?: unknown;
  proof?: unknown;
  anchors?: readonly TrustAnchor[];
  view?: VerifiedForeignStatusList | undefined;
  replay?: ForeignReplayGuard;
  audience?: string;
  request?: unknown;
  now?: Date;
}

async function run(org: Organisation, agent: Agent, call: Call = {}) {
  const view = "view" in call ? call.view : await viewOf(org);
  return verifyForeignAgent({
    credential: "credential" in call ? call.credential : agent.credential,
    proof: "proof" in call ? call.proof : await proofFor(agent),
    anchors: call.anchors ?? [org.anchor],
    statusViewFor: () => view,
    audience: call.audience ?? RECEIVER,
    request: ("request" in call ? call.request : REQUEST) as { tool: string; action: string },
    replay: call.replay ?? memoryReplayGuard(),
    now: call.now ?? NOW,
    maxProofSkewSeconds: PROOF_SKEW,
    maxClockSkewSeconds: CLOCK_SKEW,
  });
}

function mutate(credential: SignedCredential, change: (draft: Draft) => void): unknown {
  const draft = structuredClone(credential) as unknown as Draft;
  change(draft);
  return draft;
}

const denied = (code: string, extra: Record<string, unknown> = {}) => ({
  ok: false,
  error: { code, ...extra },
});

describe("verifyForeignAgent: the allowed path", () => {
  it("accepts a genuine agent of a trusted domain with no call to its issuer", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org, { index: 12 });
    const result = await run(org, agent);
    expect(result).toMatchObject({
      ok: true,
      value: {
        agentDid: agent.did,
        domain: "a.example",
        issuerDid: "did:web:a.example",
        statusListIndex: 12,
        statusAsOf: new Date("2026-10-17T11:59:50.000Z"),
      },
    });
  });

  it("accepts a credential that carries a validUntil still in the future", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org, { validUntil: "2026-10-17T13:00:00.000Z" });
    expect((await run(org, agent)).ok).toBe(true);
  });

  it("selects the right anchor among several by the issuer's exact DID", async () => {
    const orgA = makeOrganisation();
    const other = makeOrganisation({
      domain: "c.example",
      credentialIssuerDid: "did:web:c.example",
    });
    const agent = await issueAgent(orgA);
    expect((await run(orgA, agent, { anchors: [other.anchor, orgA.anchor] })).ok).toBe(true);
  });

  it("accepts an asynchronous replay guard", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    expect((await run(org, agent, { replay: memoryReplayGuard({ async: true }) })).ok).toBe(true);
  });

  it("treats an index past the end of the list as not revoked (ADR 0013)", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org, { index: 9_999_999 });
    expect((await run(org, agent)).ok).toBe(true);
  });
});

describe("verifyForeignAgent: input on the trust boundary", () => {
  it("refuses a credential that is not an object, a proof that is not a string, oversize and cyclic input", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    for (const credential of [null, undefined, "x", 7, [], true]) {
      expect(await run(org, agent, { credential })).toMatchObject(denied("MALFORMED_INPUT"));
    }
    for (const proof of [undefined, null, 7, {}, ["a.b"]]) {
      expect(await run(org, agent, { proof })).toMatchObject(denied("MALFORMED_INPUT"));
    }
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(await run(org, agent, { credential: cyclic })).toMatchObject(denied("MALFORMED_INPUT"));
    const oversized = mutate(agent.credential, (d) => (d.padding = "x".repeat(17_000)));
    expect(await run(org, agent, { credential: oversized })).toMatchObject(
      denied("MALFORMED_INPUT"),
    );
  });

  it("refuses a credential with no issuer or a non-string issuer", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    for (const issuer of [undefined, null, 5, {}, ["did:web:a.example"]]) {
      const credential = mutate(agent.credential, (d) => (d.issuer = issuer));
      expect(await run(org, agent, { credential })).toMatchObject(denied("NO_TRUST_ANCHOR"));
    }
  });
});

describe("verifyForeignAgent: who issued it", () => {
  it("refuses an issuer that is not a pinned anchor, before any signature check", async () => {
    const org = makeOrganisation();
    const stranger = makeOrganisation({ credentialIssuerDid: "did:web:evil.example" });
    const agent = await issueAgent(stranger, { issuerDid: "did:web:evil.example" });
    expect(await run(org, agent)).toMatchObject(denied("NO_TRUST_ANCHOR"));
    expect(await run(org, agent, { anchors: [] })).toMatchObject(denied("NO_TRUST_ANCHOR"));
  });

  it("refuses everything from a domain B has switched off", async () => {
    const org = makeOrganisation({ enabled: false });
    const agent = await issueAgent(org);
    expect(await run(org, agent)).toMatchObject(denied("ANCHOR_DISABLED", { domain: "a.example" }));
  });

  it("fails closed on an anchor with an unusable window", async () => {
    for (const maxStatusAgeSeconds of [0, -5, 2.5, Number.NaN]) {
      const org = makeOrganisation({ maxStatusAgeSeconds });
      const agent = await issueAgent(org);
      expect(await run(org, agent, { view: undefined })).toMatchObject(
        denied("ANCHOR_INVALID", { domain: "a.example" }),
      );
    }
  });
});

describe("verifyForeignAgent: the credential's signature", () => {
  it("refuses a credential that names the anchor's DID but was signed by another key", async () => {
    const org = makeOrganisation();
    const forged = await issueAgent(org, { signWith: generateKeyPair() });
    expect(await run(org, forged)).toMatchObject(denied("CREDENTIAL_SIGNATURE_INVALID"));
  });

  it("refuses a credential signed with the organisation's status key instead of its identity key", async () => {
    const org = makeOrganisation();
    const wrongRole = await issueAgent(org, { signWith: org.statusKeys });
    expect(await run(org, wrongRole)).toMatchObject(denied("CREDENTIAL_SIGNATURE_INVALID"));
  });

  describe("covers every field the decision relies on", () => {
    it.each([
      ["statusListIndex", (d: Draft) => (stat(d).statusListIndex = "8")],
      [
        "statusListCredential",
        (d: Draft) => (stat(d).statusListCredential = "https://evil.example/l"),
      ],
      ["statusPurpose", (d: Draft) => (stat(d).statusPurpose = "suspension")],
      ["credentialStatus removed", (d: Draft) => delete d.credentialStatus],
      [
        "embedded key",
        (d: Draft) =>
          (sub(d).publicKeyMultibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
      ],
      ["subject id", (d: Draft) => (sub(d).id = "did:web:a.example:agents:x")],
      ["validFrom", (d: Draft) => (d.validFrom = "2020-01-01T00:00:00.000Z")],
      ["validUntil added", (d: Draft) => (d.validUntil = "2099-01-01T00:00:00.000Z")],
    ])("rejects a tampered %s", async (_field, change) => {
      const org = makeOrganisation();
      const agent = await issueAgent(org);
      const credential = mutate(agent.credential, change);
      expect(await run(org, agent, { credential })).toMatchObject(
        denied("CREDENTIAL_SIGNATURE_INVALID"),
      );
    });

    it("rejects a validUntil that was signed and then deleted", async () => {
      const org = makeOrganisation();
      const agent = await issueAgent(org, { validUntil: "2026-10-17T12:30:00.000Z" });
      const credential = mutate(agent.credential, (d) => delete d.validUntil);
      expect(await run(org, agent, { credential })).toMatchObject(
        denied("CREDENTIAL_SIGNATURE_INVALID"),
      );
    });
  });
});

describe("verifyForeignAgent: the credential's subject", () => {
  it("refuses a validly signed credential whose subject is unusable", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const key = publicKeyToMultibase(agent.keys.publicKey);
    const cases: Array<[string, Record<string, unknown>]> = [
      ["no subject id", { publicKeyMultibase: key }],
      ["no embedded key", { id: agent.did }],
      ["an embedded key that is not a key", { id: agent.did, publicKeyMultibase: "not-a-key" }],
      ["a key of the wrong length", { id: agent.did, publicKeyMultibase: "z6Mkabc" }],
    ];
    for (const [label, subject] of cases) {
      const credential = await issueCustomAgent(org, agent, { subject });
      expect(await run(org, agent, { credential }), label).toMatchObject(
        denied("CREDENTIAL_SUBJECT_INVALID"),
      );
    }
  });

  it("refuses an edited subject because the signature no longer holds", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    for (const change of [
      (d: Draft) => delete d.credentialSubject,
      (d: Draft) => (d.credentialSubject = "x"),
    ]) {
      const credential = mutate(agent.credential, change);
      expect((await run(org, agent, { credential })).ok).toBe(false);
    }
  });
});

describe("verifyForeignAgent: the credential's validity period", () => {
  it("refuses an expired credential, with the boundary exclusive", async () => {
    const org = makeOrganisation();
    const expired = await issueAgent(org, { validUntil: "2026-10-17T11:59:59.000Z" });
    expect(await run(org, expired)).toMatchObject(denied("CREDENTIAL_EXPIRED"));
    const atBoundary = await issueAgent(org, { validUntil: NOW.toISOString() });
    expect(await run(org, atBoundary)).toMatchObject(denied("CREDENTIAL_EXPIRED"));
  });

  it("refuses a credential that is not valid yet, allowing only the configured skew", async () => {
    const org = makeOrganisation();
    const future = await issueAgent(org, {
      validFrom: new Date(NOW.getTime() + (CLOCK_SKEW + 1) * 1000),
    });
    expect(await run(org, future)).toMatchObject(denied("CREDENTIAL_NOT_YET_VALID"));
    const withinSkew = await issueAgent(org, {
      validFrom: new Date(NOW.getTime() + CLOCK_SKEW * 1000),
    });
    expect((await run(org, withinSkew)).ok).toBe(true);
  });

  it("refuses times it cannot read, rather than ignoring them", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    for (const validFrom of ["yesterday", "2026-10-17", "1760702400", ""]) {
      const credential = await issueCustomAgent(org, agent, { validFrom });
      expect(await run(org, agent, { credential }), validFrom).toMatchObject(
        denied("CREDENTIAL_TIME_INVALID", { reason: "validFrom is not a timestamp" }),
      );
    }
    for (const validUntil of ["soon", "2099-01-01", "", "null"]) {
      const credential = await issueCustomAgent(org, agent, { validUntil });
      expect(await run(org, agent, { credential }), validUntil).toMatchObject(
        denied("CREDENTIAL_TIME_INVALID", { reason: "validUntil is not a timestamp" }),
      );
    }
  });
});

describe("verifyForeignAgent: proof of possession", () => {
  it("refuses a copied credential presented with a proof made by some other key", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const thief = generateKeyPair();
    const proof = await proofFor(agent, { secretKey: thief.secretKey });
    expect(await run(org, agent, { proof })).toMatchObject(
      denied("PROOF_REJECTED", { reason: "SIGNATURE_INVALID" }),
    );
  });

  it("refuses a proof made for the vault's /tokens (wrong type), and the reverse is pinned by its own tests", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const proof = await buildTokenRequestProof({
      audience: RECEIVER,
      secretKey: agent.keys.secretKey,
      now: NOW,
      request: REQUEST,
    });
    expect(await run(org, agent, { proof })).toMatchObject(
      denied("PROOF_REJECTED", { reason: "WRONG_TYPE" }),
    );
  });

  it("refuses a proof addressed to someone else", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const proof = await proofFor(agent, { audience: "https://elsewhere.example/federation" });
    expect(await run(org, agent, { proof })).toMatchObject(
      denied("PROOF_REJECTED", { reason: "WRONG_AUDIENCE" }),
    );
  });

  it("refuses a stale proof and a malformed one", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const stale = await proofFor(agent, { now: new Date(NOW.getTime() - (PROOF_SKEW + 1) * 1000) });
    expect(await run(org, agent, { proof: stale })).toMatchObject(
      denied("PROOF_REJECTED", { reason: "STALE" }),
    );
    expect(await run(org, agent, { proof: "garbage" })).toMatchObject(
      denied("PROOF_REJECTED", { reason: "MALFORMED_PROOF" }),
    );
  });

  it("refuses a replayed proof, and keys the guard by agent so ids cannot collide across agents", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const replay = memoryReplayGuard();
    const proof = await proofFor(agent, { jti: "same-id" });
    expect((await run(org, agent, { proof, replay })).ok).toBe(true);
    expect(await run(org, agent, { proof, replay })).toMatchObject(denied("PROOF_REPLAYED"));

    const other = await issueAgent(org);
    const sameJti = await proofFor(other, { jti: "same-id" });
    expect((await run(org, other, { proof: sameJti, replay })).ok).toBe(true);
    expect(replay.seen).toEqual([
      `did:web:a.example|${agent.did}|same-id`,
      `did:web:a.example|${other.did}|same-id`,
    ]);
  });

  it("does not record a proof that failed verification", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const replay = memoryReplayGuard();
    const thief = generateKeyPair();
    await run(org, agent, { proof: await proofFor(agent, { secretKey: thief.secretKey }), replay });
    expect(replay.seen).toEqual([]);
  });

  it("fails closed when the replay guard is full", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    expect(await run(org, agent, { replay: memoryReplayGuard({ full: true }) })).toMatchObject(
      denied("REPLAY_GUARD_FULL"),
    );
  });
});

describe("verifyForeignAgent: replay in the last accepted second", () => {
  it("remembers a proof until it can no longer be accepted, not one second short", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const replay = expiringReplayGuard();
    const issuedAt = new Date(Math.floor(NOW.getTime() / 1000) * 1000);
    const proof = await proofFor(agent, { now: issuedAt, jti: "once" });
    expect((await run(org, agent, { proof, replay, now: issuedAt })).ok).toBe(true);

    // verifyPossessionProof floors `now` to whole seconds, so the proof is still
    // accepted half a second after iat + skew; a replay then must be refused.
    const lastAccepted = new Date(issuedAt.getTime() + PROOF_SKEW * 1000 + 500);
    expect(
      await run(org, agent, {
        proof,
        replay,
        now: lastAccepted,
        view: await viewOf(org, {}, lastAccepted),
      }),
    ).toMatchObject(denied("PROOF_REPLAYED"));

    // One second later the proof is stale on its own and is refused for that reason.
    const tooLate = new Date(issuedAt.getTime() + (PROOF_SKEW + 1) * 1000);
    expect(await run(org, agent, { proof, replay, now: tooLate })).toMatchObject(
      denied("PROOF_REJECTED", { reason: "STALE" }),
    );
  });
});

describe("verifyForeignAgent: one trusted organisation cannot speak for another's agents", () => {
  it("refuses a credential whose subject is outside its issuer's namespace", async () => {
    const orgA = makeOrganisation();
    const orgC = makeOrganisation({
      domain: "c.example",
      credentialIssuerDid: "did:web:c.example",
    });
    // C holds the key pinned for did:web:c.example and signs a credential whose
    // subject sits in A's namespace.
    const victim = await issueAgent(orgA);
    const forged = await issueCustomAgent(
      { ...orgC, identityDid: "did:web:c.example", identityKeys: orgC.identityKeys },
      victim,
      {},
    );
    const result = await run(orgC, victim, {
      credential: forged,
      anchors: [orgA.anchor, orgC.anchor],
    });
    expect(result).toMatchObject(
      denied("CREDENTIAL_SUBJECT_INVALID", { reason: "agent is not in the issuer's namespace" }),
    );
  });

  it("keys the replay guard by issuer as well as agent", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const replay = memoryReplayGuard();
    await run(org, agent, { replay });
    expect(replay.seen[0]?.startsWith("did:web:a.example|did:web:a.example:agents:")).toBe(true);
  });
});

describe("verifyForeignAgent: the proof is bound to the request B runs (ADR 0015)", () => {
  it("refuses a proof made for another action, without using it up", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const replay = memoryReplayGuard();
    const write = { tool: REQUEST.tool, action: "write" };
    const proof = await proofFor(agent, { request: write });
    expect(await run(org, agent, { proof, replay })).toMatchObject(
      denied("PROOF_REJECTED", { reason: "WRONG_REQUEST" }),
    );
    // Refused before the replay guard: nothing recorded, so the call the
    // agent really made, for the action it signed, still goes through.
    expect(replay.seen).toEqual([]);
    expect(await run(org, agent, { proof, replay, request: write })).toMatchObject({ ok: true });
  });

  it("refuses a proof made for another tool", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const proof = await proofFor(agent, { request: { tool: "stripe", action: REQUEST.action } });
    expect(await run(org, agent, { proof })).toMatchObject(
      denied("PROOF_REJECTED", { reason: "WRONG_REQUEST" }),
    );
  });

  it.each([
    ["missing", null],
    ["a string", "b-ledger:read"],
    ["an empty tool", { tool: "", action: "read" }],
    ["an oversized action", { tool: "b-ledger", action: "a".repeat(129) }],
  ])("refuses to decide when the request to check against is %s", async (_label, request) => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    expect(await run(org, agent, { request })).toMatchObject(denied("MALFORMED_INPUT"));
  });
});

describe("verifyForeignAgent: the status view must belong to the anchor", () => {
  it("refuses a view that was verified for a different list", async () => {
    const org = makeOrganisation();
    const other = makeOrganisation({ statusListId: "https://c.example/status/revocation" });
    const agent = await issueAgent(org);
    const view = await viewOf(other, { id: "https://c.example/status/revocation" });
    expect(await run(org, agent, { view })).toMatchObject(denied("STATUS_VIEW_MISMATCH"));
  });
});

describe("verifyForeignAgent: where its revocation bit lives", () => {
  it("refuses a credential with no status entry: revocation could not be checked", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org, { noStatus: true });
    expect(await run(org, agent)).toMatchObject(
      denied("STATUS_ENTRY_INVALID", { reason: "missing" }),
    );
  });

  it("refuses a signed entry that points at a list that is not the anchor's", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org, { statusListCredential: "https://evil.example/list" });
    expect(await run(org, agent)).toMatchObject(denied("STATUS_ENTRY_INVALID"));
  });

  it("refuses an index that is not a plain decimal number", async () => {
    const org = makeOrganisation();
    for (const statusListIndexText of [
      "-1",
      "1.5",
      "0x10",
      " 7",
      "7 ",
      "",
      "1e3",
      "9".repeat(16),
    ]) {
      const agent = await issueAgent(org, { statusListIndexText });
      expect(await run(org, agent), statusListIndexText).toMatchObject(
        denied("STATUS_ENTRY_INVALID"),
      );
    }
  });

  it("refuses a signed status entry whose purpose is not revocation", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    for (const entry of [{ type: "BitstringStatusListEntry", statusPurpose: "suspension" }]) {
      const credential = await issueCustomAgent(org, agent, {
        credentialStatus: {
          id: `${STATUS_LIST_ID}#7`,
          statusListIndex: "7",
          statusListCredential: STATUS_LIST_ID,
          ...entry,
        },
      });
      expect(await run(org, agent, { credential })).toMatchObject(
        denied("STATUS_ENTRY_INVALID", { reason: "not a revocation entry" }),
      );
    }
  });

  it("refuses a status entry that is not an object", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const credential = await issueCustomAgent(org, agent, { credentialStatus: null });
    expect(await run(org, agent, { credential })).toMatchObject(
      denied("STATUS_ENTRY_INVALID", { reason: "missing" }),
    );
  });
});

describe("verifyForeignAgent: post-proof denials name the verified agent", () => {
  // The gate audits these denials. The identity must come from core, which
  // read it after the signature and the proof verified, never from raw input.
  const identity = (agent: Agent) => ({
    agentDid: agent.did,
    issuerDid: "did:web:a.example",
    domain: "a.example",
  });

  it.each([
    ["AGENT_REVOKED", async (org: Organisation) => ({ view: await viewOf(org, { revoked: [7] }) })],
    ["STATUS_UNAVAILABLE", async () => ({ view: undefined })],
    [
      "STATUS_STALE",
      async (org: Organisation) => ({
        view: await viewOf(
          org,
          { validFrom: new Date(NOW.getTime() - 1_200_000) },
          new Date(NOW.getTime() - 1_200_000),
        ),
      }),
    ],
    [
      "STATUS_VIEW_MISMATCH",
      async () => ({
        view: await viewOf(makeOrganisation({ statusListId: "https://c.example/s" }), {
          id: "https://c.example/s",
        }),
      }),
    ],
  ])("%s carries agentDid, issuerDid and domain", async (code, makeCall) => {
    const org = makeOrganisation({ maxStatusAgeSeconds: 600 });
    const agent = await issueAgent(org, { index: 7 });
    expect(await run(org, agent, await makeCall(org))).toMatchObject(denied(code, identity(agent)));
  });

  it("STATUS_ENTRY_INVALID carries agentDid, issuerDid and domain", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org, { noStatus: true });
    expect(await run(org, agent)).toMatchObject(denied("STATUS_ENTRY_INVALID", identity(agent)));
  });
});

describe("verifyForeignAgent: revocation and freshness", () => {
  it("refuses a revoked agent", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org, { index: 7 });
    const view = await viewOf(org, { revoked: [7] });
    expect(await run(org, agent, { view })).toMatchObject(denied("AGENT_REVOKED"));
  });

  it("refuses when B holds no status view for the anchor at all", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    expect(await run(org, agent, { view: undefined })).toMatchObject(denied("STATUS_UNAVAILABLE"));
  });

  it("refuses an agent whose list has aged out, and recovers on a fresh list", async () => {
    const org = makeOrganisation({ maxStatusAgeSeconds: 600 });
    const agent = await issueAgent(org);
    const view = await viewOf(org);
    const later = new Date(NOW.getTime() + 700_000);
    expect(
      await run(org, agent, { view, now: later, proof: await proofFor(agent, { now: later }) }),
    ).toMatchObject(denied("STATUS_STALE"));
    const freshView = await viewOf(org, { validFrom: new Date(later.getTime() - 5_000) }, later);
    expect(
      (
        await run(org, agent, {
          view: freshView,
          now: later,
          proof: await proofFor(agent, { now: later }),
        })
      ).ok,
    ).toBe(true);
  });

  it("answers revoked, not stale, for a revoked agent even when the list has aged out", async () => {
    const org = makeOrganisation({ maxStatusAgeSeconds: 600 });
    const agent = await issueAgent(org, { index: 7 });
    const view = await viewOf(org, { revoked: [7] });
    const later = new Date(NOW.getTime() + 700_000);
    expect(
      await run(org, agent, { view, now: later, proof: await proofFor(agent, { now: later }) }),
    ).toMatchObject(denied("AGENT_REVOKED"));
  });

  it("does not let one agent's revocation affect another", async () => {
    const org = makeOrganisation();
    const other = await issueAgent(org, { index: 8 });
    const view = await viewOf(org, { revoked: [7] });
    expect((await run(org, other, { view })).ok).toBe(true);
  });
});

import type { AuditEvent } from "@custos/contracts";
import {
  type ForeignDenial,
  type ForeignReplayGuard,
  type VerifiedForeignStatusList,
} from "@custos/core";
import { describe, expect, it } from "vitest";
import type { AuditReporter } from "@custos/audit-client";
import { createForeignAgentGate, toPublicDenial } from "./gate.js";
import {
  issueAgent,
  issueList,
  makeOrganisation,
  NOW,
  proofFor,
  RECEIVER,
  type Agent,
  type Organisation,
} from "./fixtures.js";
import { createInMemoryReplayGuard } from "./replay-guard.js";
import { createStatusCache } from "./status-cache.js";

interface Harness {
  readonly org: Organisation;
  readonly events: AuditEvent[];
  readonly denied: string[];
  /** Move `now` to age the gate's clock. */
  readonly clock: { now: Date };
  readonly gate: ReturnType<typeof createForeignAgentGate>;
}

async function harness(
  options: {
    revoked?: readonly number[];
    withView?: boolean;
    view?: VerifiedForeignStatusList;
    maxStatusAgeSeconds?: number;
    replay?: ForeignReplayGuard;
    audit?: AuditReporter;
    org?: Organisation;
  } = {},
): Promise<Harness> {
  const org =
    options.org ?? makeOrganisation({ maxStatusAgeSeconds: options.maxStatusAgeSeconds ?? 3600 });
  const events: AuditEvent[] = [];
  const denied: string[] = [];
  const clock = { now: NOW };
  const view =
    options.view ??
    (options.withView === false ? undefined : await viewFrom(org, options.revoked ?? [], NOW));
  const gate = createForeignAgentGate({
    anchors: [org.anchor],
    statusViewFor: () => view,
    audience: RECEIVER,
    replay: options.replay ?? createInMemoryReplayGuard(),
    now: () => clock.now,
    maxProofSkewSeconds: 30,
    maxClockSkewSeconds: 5,
    audit: options.audit ?? { report: (event) => void events.push(event) },
    onDenied: (denial) => void denied.push(denial.code),
  });
  return { org, events, denied, clock, gate };
}

async function viewFrom(org: Organisation, revoked: readonly number[], at: Date) {
  const cache = createStatusCache({
    anchors: [org.anchor],
    pollIntervalMs: 60_000,
    maxClockSkewSeconds: 5,
    now: () => at,
    fetchImpl: (async () =>
      new Response(JSON.stringify(await issueList(org, { revoked, now: NOW })))) as typeof fetch,
  });
  await cache.pollOnce(org.anchor);
  return cache.viewFor(org.anchor);
}

async function call(agent: Agent, extra: { now?: Date; tool?: string; action?: string } = {}) {
  return {
    credential: agent.credential,
    proof: await proofFor(agent, extra.now === undefined ? {} : { now: extra.now }),
    ...(extra.tool === undefined ? {} : { tool: extra.tool }),
    ...(extra.action === undefined ? {} : { action: extra.action }),
  };
}

describe("createForeignAgentGate: allow", () => {
  it("lets a valid agent through and audits the allow with what was attempted", async () => {
    const { org, gate, events, denied } = await harness();
    const agent = await issueAgent(org);
    const result = await gate.check(await call(agent, { tool: "mock-slack", action: "post" }));
    expect(result).toMatchObject({ ok: true, value: { agentDid: agent.did, domain: "a.example" } });
    expect(denied).toEqual([]);
    expect(events).toEqual([
      {
        agentDid: agent.did,
        tool: "mock-slack",
        action: "post",
        dataCategories: [],
        policy: { rule: "foreign:a.example", decision: "allow" },
        reason: expect.stringContaining("issuer=did:web:a.example"),
      },
    ]);
  });

  it("audits a call with no tool or action as foreign.call, without a tool field", async () => {
    const { org, gate, events } = await harness();
    await gate.check(await call(await issueAgent(org)));
    expect(events[0]).toMatchObject({ action: "foreign.call" });
    expect(events[0]).not.toHaveProperty("tool");
  });
});

describe("createForeignAgentGate: denials after the proof verified are audited", () => {
  it("answers 403 AGENT_REVOKED for a revoked agent and audits who, under which domain", async () => {
    const { org, gate, events } = await harness({ revoked: [7] });
    const agent = await issueAgent(org, { index: 7 });
    const result = await gate.check(await call(agent, { tool: "stripe" }));
    expect(result).toMatchObject({ ok: false, error: { status: 403, code: "AGENT_REVOKED" } });
    expect(events).toEqual([
      {
        agentDid: agent.did,
        tool: "stripe",
        action: "foreign.call",
        dataCategories: [],
        policy: { rule: "foreign:a.example", decision: "deny" },
        reason: "issuer=did:web:a.example code=AGENT_REVOKED",
      },
    ]);
  });

  it("does not let one agent's revocation touch another", async () => {
    const { org, gate } = await harness({ revoked: [7] });
    expect((await gate.check(await call(await issueAgent(org, { index: 8 })))).ok).toBe(true);
  });

  it("answers 503 UNAVAILABLE and audits when no status view is held", async () => {
    const { org, gate, events } = await harness({ withView: false });
    const agent = await issueAgent(org);
    const result = await gate.check(await call(agent));
    expect(result).toMatchObject({ ok: false, error: { status: 503, code: "UNAVAILABLE" } });
    expect(events[0]).toMatchObject({
      agentDid: agent.did,
      reason: "issuer=did:web:a.example code=STATUS_UNAVAILABLE",
    });
  });

  it("answers 503 UNAVAILABLE and audits when the view has aged out", async () => {
    const h = await harness({ maxStatusAgeSeconds: 600 });
    const agent = await issueAgent(h.org);
    h.clock.now = new Date(NOW.getTime() + 700_000);
    const result = await h.gate.check(await call(agent, { now: h.clock.now }));
    expect(result).toMatchObject({ ok: false, error: { status: 503, code: "UNAVAILABLE" } });
    expect(h.events).toEqual([
      expect.objectContaining({
        agentDid: agent.did,
        reason: "issuer=did:web:a.example code=STATUS_STALE",
      }),
    ]);
  });

  it("still tells a revoked agent it is revoked after the view has aged out", async () => {
    const h = await harness({ maxStatusAgeSeconds: 600, revoked: [7] });
    const agent = await issueAgent(h.org, { index: 7 });
    h.clock.now = new Date(NOW.getTime() + 700_000);
    const result = await h.gate.check(await call(agent, { now: h.clock.now }));
    expect(result).toMatchObject({ ok: false, error: { status: 403, code: "AGENT_REVOKED" } });
  });

  it("answers 503 and audits when the view was verified for another list", async () => {
    const other = makeOrganisation({ statusListId: "https://c.example/s" });
    const wrongView = await viewFrom(other, [], NOW);
    const h = await harness({ view: wrongView });
    const agent = await issueAgent(h.org);
    const result = await h.gate.check(await call(agent));
    expect(result).toMatchObject({ ok: false, error: { status: 503, code: "UNAVAILABLE" } });
    expect(h.events[0]).toMatchObject({
      agentDid: agent.did,
      reason: "issuer=did:web:a.example code=STATUS_VIEW_MISMATCH",
    });
  });

  it("answers 401 and audits a credential with no status entry", async () => {
    const { org, gate, events } = await harness();
    const agent = await issueAgent(org, { noStatus: true });
    const result = await gate.check(await call(agent));
    expect(result).toMatchObject({ ok: false, error: { status: 401, code: "UNAUTHORIZED" } });
    expect(events[0]).toMatchObject({
      agentDid: agent.did,
      reason: "issuer=did:web:a.example code=STATUS_ENTRY_INVALID missing",
    });
  });
});

describe("createForeignAgentGate: earlier failures are logged, never audited", () => {
  async function refusedWith(make: (h: Harness) => Promise<unknown>) {
    const h = await harness();
    const result = await h.gate.check((await make(h)) as Parameters<typeof h.gate.check>[0]);
    return { result, h };
  }

  it("a tampered credential: 401, no audit record", async () => {
    const { result, h } = await refusedWith(async ({ org }) => {
      const agent = await issueAgent(org);
      const tampered = structuredClone(agent.credential) as unknown as {
        credentialSubject: { id: string };
      };
      tampered.credentialSubject.id = "did:web:a.example:agents:someone-else";
      return { credential: tampered, proof: await proofFor(agent) };
    });
    expect(result).toMatchObject({ ok: false, error: { status: 401, code: "UNAUTHORIZED" } });
    expect(h.events).toEqual([]);
    expect(h.denied).toEqual(["CREDENTIAL_SIGNATURE_INVALID"]);
  });

  it("a credential from an organisation B does not trust: 401, no audit record", async () => {
    const { result, h } = await refusedWith(async () => {
      const stranger = makeOrganisation({ credentialIssuerDid: "did:web:evil.example" });
      const agent = await issueAgent(stranger);
      return call(agent);
    });
    expect(result).toMatchObject({ ok: false, error: { status: 401, code: "UNAUTHORIZED" } });
    expect(h.events).toEqual([]);
  });

  it("a trusted organisation switched off: 401, no audit record", async () => {
    const org = makeOrganisation({ enabled: false });
    const h = await harness({ org });
    const result = await h.gate.check(await call(await issueAgent(org)));
    expect(result).toMatchObject({ ok: false, error: { status: 401, code: "UNAUTHORIZED" } });
    expect(h.denied).toEqual(["ANCHOR_DISABLED"]);
    expect(h.events).toEqual([]);
  });

  it("a proof signed by someone who does not hold the agent's key: 401, no audit record", async () => {
    const { result, h } = await refusedWith(async ({ org }) => {
      const agent = await issueAgent(org);
      const thief = await issueAgent(org);
      return { credential: agent.credential, proof: await proofFor(thief) };
    });
    expect(result).toMatchObject({ ok: false, error: { status: 401 } });
    expect(h.events).toEqual([]);
    expect(h.denied).toEqual(["PROOF_REJECTED"]);
  });

  it("a replayed proof: 401 the second time, and only the first call is audited", async () => {
    const h = await harness();
    const agent = await issueAgent(h.org);
    const first = await call(agent);
    expect((await h.gate.check(first)).ok).toBe(true);
    const second = await h.gate.check(first);
    expect(second).toMatchObject({ ok: false, error: { status: 401, code: "UNAUTHORIZED" } });
    expect(h.denied).toEqual(["PROOF_REPLAYED"]);
    expect(h.events).toHaveLength(1);
  });

  it("a proof addressed to another receiver: 401, no audit record", async () => {
    const h = await harness();
    const agent = await issueAgent(h.org);
    const { buildForeignCallProof } = await import("@custos/core");
    const proof = await buildForeignCallProof({
      audience: "https://elsewhere.example/federation",
      secretKey: agent.keys.secretKey,
      now: NOW,
    });
    const result = await h.gate.check({ credential: agent.credential, proof });
    expect(result).toMatchObject({ ok: false, error: { status: 401 } });
    expect(h.events).toEqual([]);
  });

  it.each([
    ["no credential", undefined, "p"],
    ["a string credential", "x", "p"],
    ["a null credential", null, "p"],
    ["an array credential", [], "p"],
    ["a non-string proof", {}, 7],
    ["an oversized credential", { issuer: "x".repeat(20_000) }, "p"],
  ])("%s: 401, no audit record, no throw", async (_label, credential, proof) => {
    const h = await harness();
    const result = await h.gate.check({ credential, proof });
    expect(result).toMatchObject({ ok: false, error: { status: 401, code: "UNAUTHORIZED" } });
    expect(h.events).toEqual([]);
  });

  it("a full replay guard: 503 and refused, not audited", async () => {
    const h = await harness({ replay: createInMemoryReplayGuard({ maxEntries: 1 }) });
    const first = await issueAgent(h.org);
    expect((await h.gate.check(await call(first))).ok).toBe(true);
    const second = await h.gate.check(await call(await issueAgent(h.org)));
    expect(second).toMatchObject({ ok: false, error: { status: 503, code: "UNAVAILABLE" } });
    expect(h.denied).toEqual(["REPLAY_GUARD_FULL"]);
    expect(h.events).toHaveLength(1);
  });
});

describe("createForeignAgentGate: what a caller can learn", () => {
  it("answers every credential, proof and anchor failure identically", async () => {
    const h = await harness();
    const agent = await issueAgent(h.org);
    const stranger = await issueAgent(
      makeOrganisation({ credentialIssuerDid: "did:web:evil.example" }),
    );
    const other = await issueAgent(h.org);
    const tampered = structuredClone(agent.credential) as unknown as { id: string };
    tampered.id = "urn:uuid:changed";

    const answers = await Promise.all([
      h.gate.check(await call(stranger)),
      h.gate.check({ credential: tampered, proof: await proofFor(agent) }),
      h.gate.check({ credential: agent.credential, proof: await proofFor(other) }),
      h.gate.check({ credential: "nope", proof: "nope" }),
    ]);
    const bodies = answers.map((answer) =>
      answer.ok ? "allowed" : `${answer.error.status} ${answer.error.code}`,
    );
    expect(new Set(bodies)).toEqual(new Set(["401 UNAUTHORIZED"]));
  });
});

describe("createForeignAgentGate: audit and logging never decide the answer", () => {
  it("still answers when the audit reporter throws", async () => {
    const h = await harness({
      audit: {
        report: () => {
          throw new Error("audit down");
        },
      },
    });
    expect((await h.gate.check(await call(await issueAgent(h.org)))).ok).toBe(true);
  });

  it("still answers when the denial log callback throws", async () => {
    const org = makeOrganisation();
    const gate = createForeignAgentGate({
      anchors: [org.anchor],
      statusViewFor: () => undefined,
      audience: RECEIVER,
      replay: createInMemoryReplayGuard(),
      now: () => NOW,
      maxProofSkewSeconds: 30,
      maxClockSkewSeconds: 5,
      onDenied: () => {
        throw new Error("logger down");
      },
    });
    const result = await gate.check({ credential: "x", proof: "y" });
    expect(result).toMatchObject({ ok: false, error: { status: 401 } });
  });

  it("works with no audit reporter at all", async () => {
    const org = makeOrganisation();
    const view = await viewFrom(org, [], NOW);
    const gate = createForeignAgentGate({
      anchors: [org.anchor],
      statusViewFor: () => view,
      audience: RECEIVER,
      replay: createInMemoryReplayGuard(),
      now: () => NOW,
      maxProofSkewSeconds: 30,
      maxClockSkewSeconds: 5,
    });
    expect((await gate.check(await call(await issueAgent(org)))).ok).toBe(true);
  });

  it("fails closed with a 503, and does not throw, when the replay store fails", async () => {
    const h = await harness({
      replay: {
        record: () => Promise.reject(new Error("redis down")),
      },
    });
    const result = await h.gate.check(await call(await issueAgent(h.org)));
    expect(result).toMatchObject({
      ok: false,
      error: { status: 503, code: "UNAVAILABLE", denial: { code: "GATE_FAILURE" } },
    });
    expect(h.events).toEqual([]);
    expect(h.denied).toEqual(["GATE_FAILURE"]);
  });

  it("returns the precise reason for the log but only the coarse code for the response", async () => {
    const h = await harness({ withView: false });
    const result = await h.gate.check(await call(await issueAgent(h.org)));
    expect(result).toMatchObject({
      ok: false,
      error: { code: "UNAVAILABLE", denial: { code: "STATUS_UNAVAILABLE" } },
    });
  });
});

describe("toPublicDenial", () => {
  const who = {
    agentDid: "did:web:a.example:agents:1",
    issuerDid: "did:web:a.example",
    domain: "a.example",
  };
  // Keyed by every denial code: a new core code fails typecheck here until it is mapped.
  const everyDenial = {
    MALFORMED_INPUT: { code: "MALFORMED_INPUT", reason: "x" },
    NO_TRUST_ANCHOR: { code: "NO_TRUST_ANCHOR" },
    ANCHOR_DISABLED: { code: "ANCHOR_DISABLED", domain: "a" },
    ANCHOR_INVALID: { code: "ANCHOR_INVALID", domain: "a" },
    CREDENTIAL_SIGNATURE_INVALID: { code: "CREDENTIAL_SIGNATURE_INVALID", reason: "x" },
    CREDENTIAL_SUBJECT_INVALID: { code: "CREDENTIAL_SUBJECT_INVALID", reason: "x" },
    CREDENTIAL_TIME_INVALID: { code: "CREDENTIAL_TIME_INVALID", reason: "x" },
    CREDENTIAL_NOT_YET_VALID: { code: "CREDENTIAL_NOT_YET_VALID" },
    CREDENTIAL_EXPIRED: { code: "CREDENTIAL_EXPIRED" },
    PROOF_REJECTED: { code: "PROOF_REJECTED", reason: "BAD_SIGNATURE" },
    PROOF_REPLAYED: { code: "PROOF_REPLAYED" },
    REPLAY_GUARD_FULL: { code: "REPLAY_GUARD_FULL" },
    STATUS_ENTRY_INVALID: { code: "STATUS_ENTRY_INVALID", reason: "x", ...who },
    STATUS_UNAVAILABLE: { code: "STATUS_UNAVAILABLE", ...who },
    STATUS_VIEW_MISMATCH: { code: "STATUS_VIEW_MISMATCH", ...who },
    AGENT_REVOKED: { code: "AGENT_REVOKED", ...who },
    STATUS_STALE: { code: "STATUS_STALE", ...who },
  } as unknown as { [C in ForeignDenial["code"]]: Extract<ForeignDenial, { code: C }> };

  const expected: Record<ForeignDenial["code"], number> = {
    MALFORMED_INPUT: 401,
    NO_TRUST_ANCHOR: 401,
    ANCHOR_DISABLED: 401,
    ANCHOR_INVALID: 401,
    CREDENTIAL_SIGNATURE_INVALID: 401,
    CREDENTIAL_SUBJECT_INVALID: 401,
    CREDENTIAL_TIME_INVALID: 401,
    CREDENTIAL_NOT_YET_VALID: 401,
    CREDENTIAL_EXPIRED: 401,
    PROOF_REJECTED: 401,
    PROOF_REPLAYED: 401,
    STATUS_ENTRY_INVALID: 401,
    REPLAY_GUARD_FULL: 503,
    STATUS_UNAVAILABLE: 503,
    STATUS_VIEW_MISMATCH: 503,
    STATUS_STALE: 503,
    AGENT_REVOKED: 403,
  };

  it.each(Object.entries(everyDenial))("maps %s", (code, denial) => {
    expect(toPublicDenial(denial).status).toBe(expected[code as ForeignDenial["code"]]);
  });

  it("only AGENT_REVOKED is told apart from the generic refusals", () => {
    const codes = Object.values(everyDenial).map((denial) => toPublicDenial(denial).code);
    expect(codes.filter((code) => code === "AGENT_REVOKED")).toHaveLength(1);
  });
});

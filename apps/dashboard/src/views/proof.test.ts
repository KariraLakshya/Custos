import { describe, expect, it } from "vitest";
import type { AuditRecord } from "@custos/core";
import type { LedgerCheck, Source } from "./inputs.js";
import { ledgerVerdict, proofView } from "./proof.js";
import { checkLedger, loadFixture, ok } from "./test-fixtures.js";

const clean = loadFixture("clean");
const delegated = loadFixture("delegated");
const BILLING = "did:web:localhost%3A4001:agents:6f1d2c3b-0000-4000-8000-00000000a1b2";

async function proofOf(name: Parameters<typeof loadFixture>[0], agentDid?: string) {
  const fixture = loadFixture(name);
  return proofView({
    ledger: ok(await checkLedger(fixture)),
    agents: ok(fixture.agents),
    ...(agentDid === undefined ? {} : { agentDid }),
  });
}

function verifiedWith(records: AuditRecord[], headSeq = records.length): Source<LedgerCheck> {
  return ok({
    ok: true,
    ledger: {
      records: records.map((record, i) => ({ seq: i + 1, record })),
      headSeq,
      unsealedCount: headSeq,
      log: "did:web:localhost%3A4004",
      publishedKey: "z",
      servedSeal: null,
    },
    delegations: [],
  });
}

describe("Proof, against the recorded fixtures", () => {
  it("clean: verified, in green, with the seal and the independent check", async () => {
    const view = await proofOf("clean");
    expect(view.result).toEqual({
      tone: "green",
      icon: "✓",
      headline: "✓ Verified",
      lines: [
        "7 entries · none changed since they were sealed",
        "last sealed 14:05 · 1 newer entry not sealed yet",
        "The dashboard checks this itself and starts fresh when it restarts. For an independent check, run: custos audit-log",
      ],
    });
  });

  it("clean: one sentence per event, newest first, by name", async () => {
    const view = await proofOf("clean");
    if (view.entries.state !== "ok") throw new Error("expected entries");
    expect(view.entries.data.items.map((i) => `${i.time} ${i.sentence}`)).toEqual([
      "14:06 billing-bot asked to use mock-database (query): refused. This agent, or an agent it is acting for, has been cut off from every tool.",
      "14:05 alice@company.com cut off billing-bot: key leaked",
      "14:03 billing-bot asked to use stripe (list-customers): refused. This agent has not been given this tool.",
      "14:02 billing-bot used mock-database (query): allowed",
      "14:01 alice@company.com gave billing-bot mock-database",
      "14:00 alice@company.com registered billing-bot",
      "14:00 identity reserved billing-bot&#39;s place on the revocation list",
    ]);
    expect(view.entries.data.empty).toBeUndefined();
    expect(view.filter).toEqual([{ did: BILLING, label: "billing-bot" }]);
  });

  it("clean: the raw record is one click away, escaped", async () => {
    const view = await proofOf("clean");
    if (view.entries.state !== "ok") throw new Error("expected entries");
    const raw = view.entries.data.items.find((i) => i.seq === 6)!.raw;
    expect(raw).toContain("&quot;action&quot;: &quot;agents.revoke&quot;");
    expect(raw).not.toContain('"');
  });

  it("tampered: red, says which entry, shows no entries", async () => {
    const view = await proofOf("tampered");
    expect(view.result).toEqual({
      tone: "red",
      icon: "✗",
      headline: "✗ Tampered",
      lines: [
        "Entry #4 does not match its seal.",
        "Next: Do not delete or repair anything. Keep the audit database as it is and tell whoever is responsible for security.",
        "Code: PAYLOAD_MISMATCH",
      ],
    });
    expect(view.entries).toEqual({
      state: "unreadable",
      tone: "red",
      text: "The entries are not shown, because the record did not verify.",
    });
  });

  it("truncated: red, the deleted entries named", async () => {
    const view = await proofOf("truncated");
    expect(view.result.tone).toBe("red");
    expect(view.result.headline).toBe("✗ Tampered");
    expect(view.result.lines[0]).toBe(
      "The newest entries were deleted: a seal covers up to entry #6, but the record stops at #5.",
    );
    expect(view.result.lines[2]).toBe("Code: TRUNCATED");
  });

  it("delegated: verified, and the chain reads person → agent → agent", async () => {
    const view = await proofOf("delegated");
    expect(view.result.headline).toBe("✓ Verified");
    expect(view.result.lines[1]).toBe("last sealed 14:06");
    if (view.entries.state !== "ok") throw new Error("expected entries");
    expect(view.entries.data.items.slice(0, 2).map((i) => i.sentence)).toEqual([
      "helper-bot used mock-database (query) for alice@company.com → billing-bot → helper-bot: allowed",
      "helper-bot was given a pass for mock-database (query) for alice@company.com → billing-bot → helper-bot: allowed",
    ]);
  });

  it("the filter narrows the list to one agent", async () => {
    const view = await proofOf("delegated", BILLING);
    if (view.entries.state !== "ok") throw new Error("expected entries");
    expect(view.entries.data.items.map((i) => i.seq)).toEqual([3, 2, 1]);
    const nobody = await proofOf("clean", "did:web:localhost%3A4001:agents:nobody");
    if (nobody.entries.state !== "ok") throw new Error("expected entries");
    expect(nobody.entries.data.empty).toBe("No entries for this agent.");
  });

  it("needs a person: a seal key the dashboard did not pin", async () => {
    const otherKey = delegated.didDocuments.identity.verificationMethod[0]!.publicKeyMultibase;
    const view = proofView({
      ledger: ok(await checkLedger(clean, { trustedKey: otherKey })),
      agents: ok(clean.agents),
    });
    expect(view.result.headline).toBe("! Needs a person");
    expect(view.result.tone).toBe("red");
    expect(view.result.lines[2]).toBe("Code: SEAL_INVALID/UNTRUSTED_KEY");
    expect(view.result.lines[1]).toContain("--accept-key");
  });

  it("a log whose hand-offs cannot be checked is not shown as verified", () => {
    const verdict = ledgerVerdict(
      ok({ ok: false, error: { code: "DELEGATION_UNCHECKABLE", reason: "x" } }),
    );
    expect(verdict.kind).toBe("cannot-check");
  });
});

describe("Proof, every state", () => {
  it("loading says Checking…, never an empty list", () => {
    const view = proofView({ ledger: { state: "loading" }, agents: { state: "loading" } });
    expect(view.result.headline).toBe("Checking…");
    expect(view.entries).toEqual({ state: "loading", text: "Checking…" });
  });

  it("the audit service not answering: red, Cannot check right now", () => {
    const view = proofView({
      ledger: { state: "failed", service: "audit" },
      agents: ok(clean.agents),
    });
    expect(view.result.tone).toBe("red");
    expect(view.result.headline).toBe("Cannot check right now");
    expect(view.entries.state).toBe("unreadable");
  });

  it("a group without audit:read is told so, not shown an empty log", () => {
    for (const ledger of [
      { state: "forbidden", service: "audit" } as const,
      ok<LedgerCheck>({ ok: false, error: { code: "BAD_RESPONSE", reason: "x", status: 401 } }),
    ]) {
      const view = proofView({ ledger, agents: ok(clean.agents) });
      expect(view.result.headline).toBe("Your group cannot see the audit record.");
      expect(view.entries).toEqual({
        state: "forbidden",
        text: "Your group cannot see the audit record. Ask whoever runs Custos.",
      });
    }
  });

  it("an empty log says when the first entry appears", () => {
    const view = proofView({ ledger: verifiedWith([]), agents: ok({ agents: [] }) });
    expect(view.result.lines[0]).toBe("0 entries · none changed since they were sealed");
    expect(view.result.lines[1]).toBe("not sealed yet");
    if (view.entries.state !== "ok") throw new Error("expected entries");
    expect(view.entries.data.empty).toBe(
      "No entries yet. The first one appears when an agent makes a call.",
    );
  });

  it("one entry, all unsealed", () => {
    const record: AuditRecord = {
      agentDid: BILLING,
      authorityChain: [BILLING],
      action: "query",
      dataCategories: [],
      policy: { rule: "scoped-token", decision: "allow" },
      recordedAt: "2026-11-20T14:00:00.000Z",
    };
    const view = proofView({ ledger: verifiedWith([record]), agents: { state: "loading" } });
    expect(view.result.lines[0]).toBe("1 entry · none changed since they were sealed");
  });
});

describe("Proof escapes what came over the network", () => {
  const evil: AuditRecord = {
    principal: { kind: "operator", id: "k", name: "<script>alert(1)</script>" },
    agentDid: BILLING,
    authorityChain: [],
    action: "agents.revoke",
    dataCategories: [],
    policy: { rule: "control-plane-scope:agents:revoke", decision: "allow" },
    reason: "<img src=x onerror=alert(1)>",
    recordedAt: `2026-11-20T14:00:00.000Z`,
  };

  it("a <script> operator name and reason are shown as text", () => {
    const view = proofView({ ledger: verifiedWith([evil]), agents: ok(clean.agents) });
    if (view.entries.state !== "ok") throw new Error("expected entries");
    const sentence = view.entries.data.items[0]!.sentence;
    expect(sentence).toBe(
      "&lt;script&gt;alert(1)&lt;/script&gt; cut off billing-bot: &lt;img src=x onerror=alert(1)&gt;",
    );
    expect(view.entries.data.items[0]!.raw).not.toMatch(/<script>|<img/);
  });

  it("a <script> agent name is never shown: the agent reads as unnamed", () => {
    const agents = { agents: [{ did: BILLING, name: "<script>x</script>" }] };
    const view = proofView({ ledger: verifiedWith([evil]), agents: ok(agents) });
    expect(view.filter[0]!.label).toBe("unnamed · …a1b2");
  });

  it("bidi and C1 controls in the raw record are written out, not left in the page", () => {
    const sneaky = {
      ...evil,
      reason: `a${String.fromCodePoint(0x202e)}b${String.fromCodePoint(0x85)}`,
    };
    const view = proofView({ ledger: verifiedWith([sneaky]), agents: ok(clean.agents) });
    if (view.entries.state !== "ok") throw new Error("expected entries");
    const raw = view.entries.data.items[0]!.raw;
    expect(raw).toContain("a\\u202eb\\u0085");
    expect(raw).not.toContain(String.fromCodePoint(0x202e));
  });
});

describe("ledgerVerdict puts every failure in one of the three kinds", () => {
  const cases: [LedgerCheck & { ok: false }, string][] = [
    [{ ok: false, error: { code: "UNREACHABLE", reason: "x" } }, "cannot-check"],
    [{ ok: false, error: { code: "BAD_RESPONSE", reason: "x" } }, "cannot-check"],
    [{ ok: false, error: { code: "BAD_RESPONSE", reason: "x", status: 403 } }, "forbidden"],
    [{ ok: false, error: { code: "SEAL_STORE_UNREACHABLE", reason: "x" } }, "cannot-check"],
    [{ ok: false, error: { code: "DELEGATION_UNCHECKABLE", reason: "x" } }, "cannot-check"],
    [
      { ok: false, error: { code: "SEAL_INVALID", error: { code: "UNTRUSTED_KEY", key: "z" } } },
      "needs-a-person",
    ],
    [
      { ok: false, error: { code: "SEAL_INVALID", error: { code: "SIGNATURE_INVALID" } } },
      "tampered",
    ],
    [{ ok: false, error: { code: "SEQUENCE_GAP", expected: 2, found: 3 } }, "tampered"],
    [{ ok: false, error: { code: "PAYLOAD_MISMATCH", seq: 4 } }, "tampered"],
    [{ ok: false, error: { code: "TRUNCATED", sealSeq: 6, headSeq: 5 } }, "tampered"],
    [{ ok: false, error: { code: "DIVERGED", seq: 3 } }, "tampered"],
    [{ ok: false, error: { code: "MALFORMED_ENTRY", index: 0, reason: "x" } }, "tampered"],
    [{ ok: false, error: { code: "MALFORMED_RECORD", seq: 2 } }, "tampered"],
    [{ ok: false, error: { code: "DELEGATION_INVALID", seq: 5, reason: "x" } }, "tampered"],
    [{ ok: false, error: { code: "DELEGATION_UNLINKED", seq: 6 } }, "tampered"],
  ];

  it.each(cases)("%j is %s", (check, kind) => {
    expect(ledgerVerdict(ok(check)).kind).toBe(kind);
  });

  it("every tampered or cannot-check verdict is red on Proof", () => {
    for (const [check, kind] of cases) {
      if (kind === "forbidden") continue;
      expect(proofView({ ledger: ok(check), agents: { state: "loading" } }).result.tone).toBe(
        "red",
      );
    }
  });
});

import { describe, expect, it } from "vitest";
import type { AuditLogError } from "./audit-log.js";
import { auditFailureWords, explainAuditFailure } from "./audit-words.js";

// One of every failure `custos audit-log` can report. The switch in
// `auditFailureWords` is exhaustive at compile time; this list proves each
// case's words at run time.
const tampered: AuditLogError[] = [
  { code: "SEQUENCE_GAP", expected: 57, found: 58 },
  { code: "PAYLOAD_MISMATCH", seq: 57 },
  { code: "TRUNCATED", sealSeq: 140, headSeq: 120 },
  { code: "DIVERGED", seq: 57 },
  { code: "MALFORMED_ENTRY", index: 3, reason: "x" },
  { code: "MALFORMED_RECORD", seq: 57 },
  { code: "SEAL_INVALID", error: { code: "SIGNATURE_INVALID" } },
  { code: "SEAL_INVALID", error: { code: "WRONG_LOG" } },
  { code: "SEAL_INVALID", error: { code: "MALFORMED_SEAL", reason: "x" } },
  { code: "DELEGATION_INVALID", seq: 57, reason: "x" },
  { code: "DELEGATION_UNLINKED", seq: 57 },
];
const cannotCheck: AuditLogError[] = [
  { code: "UNREACHABLE", reason: "x" },
  { code: "BAD_RESPONSE", reason: "x" },
  { code: "SEAL_STORE_UNREACHABLE", reason: "x" },
  { code: "DELEGATION_UNCHECKABLE", reason: "x" },
];
const needsAPerson: AuditLogError[] = [
  { code: "KEY_CHANGED", previous: ["z6MkOld"], current: "z6MkNew" },
  { code: "SEAL_INVALID", error: { code: "UNTRUSTED_KEY", key: "z6MkNew" } },
];

describe("auditFailureWords (ADR 0022 §6)", () => {
  it.each(tampered)("$code is tampering, and says to keep the evidence", (error) => {
    const words = auditFailureWords(error);
    expect(words.kind).toBe("tampered");
    expect(words.nextStep).toMatch(/^Do not delete or repair anything\./);
  });

  it.each(cannotCheck)("$code is a check that could not be done, not tampering", (error) => {
    const words = auditFailureWords(error);
    expect(words.kind).toBe("cannot-check");
    expect(words.meaning).not.toMatch(/changed|deleted|rewritten/);
  });

  // A new seal key is never reported as tampering, and never as fine.
  it.each(needsAPerson)("$code needs a person to compare the key", (error) => {
    expect(auditFailureWords(error).kind).toBe("needs-a-person");
  });

  it.each([...tampered, ...cannotCheck, ...needsAPerson])(
    "$code is said in words, with a next step and its code",
    (error) => {
      const { meaning, nextStep, code } = auditFailureWords(error);
      expect(meaning).not.toMatch(/[A-Z]{2,}_[A-Z_]+/);
      expect(meaning.length).toBeGreaterThan(20);
      expect(nextStep.length).toBeGreaterThan(20);
      expect(code.startsWith(error.code)).toBe(true);
    },
  );

  it("names the entry, so a person can find it", () => {
    expect(auditFailureWords({ code: "PAYLOAD_MISMATCH", seq: 57 }).meaning).toBe(
      "Entry #57 was changed after it was written.",
    );
    expect(auditFailureWords({ code: "TRUNCATED", sealSeq: 140, headSeq: 120 }).meaning).toContain(
      "up to entry #140, but the record stops at #120",
    );
  });

  it("carries the seal's own code after the slash", () => {
    expect(auditFailureWords({ code: "SEAL_INVALID", error: { code: "WRONG_LOG" } }).code).toBe(
      "SEAL_INVALID/WRONG_LOG",
    );
  });

  // Reasons come from a service or the network: never onto the terminal.
  it("never prints an error's free-text reason", () => {
    const hostile = "\u001b[2J rm -rf";
    for (const error of [
      { code: "UNREACHABLE", reason: hostile },
      { code: "MALFORMED_ENTRY", index: 1, reason: hostile },
      { code: "DELEGATION_INVALID", seq: 1, reason: hostile },
      { code: "SEAL_INVALID", error: { code: "MALFORMED_SEAL", reason: hostile } },
    ] satisfies AuditLogError[]) {
      expect(explainAuditFailure(error)).not.toContain("\u001b");
    }
  });
});

describe("explainAuditFailure", () => {
  it("prints the headline, the next step and the code", () => {
    expect(explainAuditFailure({ code: "DIVERGED", seq: 9 })).toBe(
      [
        "Tampered: The record was rewritten: entry #9 is not the one that was sealed.",
        "Next: Do not delete or repair anything. Keep the audit database as it is and tell whoever is responsible for security.",
        "Code: DIVERGED",
        "",
      ].join("\n"),
    );
    expect(explainAuditFailure({ code: "UNREACHABLE", reason: "x" })).toMatch(/^Cannot check: /);
    expect(explainAuditFailure({ code: "KEY_CHANGED", previous: [], current: "z6MkNew" })).toMatch(
      /^Needs a person: /,
    );
  });
});

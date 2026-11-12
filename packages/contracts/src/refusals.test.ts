import { describe, expect, it } from "vitest";
import { REFUSAL_REASONS, REFUSALS, UNKNOWN_REFUSAL, refusalFor } from "./refusals.js";

const everyEntry = [
  ...Object.entries(REFUSALS),
  ...Object.entries(REFUSAL_REASONS).flatMap(([code, reasons]) =>
    Object.entries(reasons).map(([reason, entry]) => [`${code}/${reason}`, entry] as const),
  ),
];

describe("the refusal catalogue", () => {
  it.each(everyEntry)("%s says what it means, what to do next, and how serious it is", (_, e) => {
    expect(e.meaning.length).toBeGreaterThan(10);
    expect(e.nextStep.length).toBeGreaterThan(10);
    expect(["normal", "alarm"]).toContain(e.severity);
  });

  it.each(everyEntry)("%s is written in words, not codes", (_, e) => {
    // A person reads these: no SHOUTING_CODES inside the meaning.
    expect(e.meaning).not.toMatch(/\b[A-Z]{3,}_[A-Z_]+\b/);
  });

  it("only files reasons under codes that exist", () => {
    for (const code of Object.keys(REFUSAL_REASONS)) expect(REFUSALS).toHaveProperty(code);
  });

  it("shows the product working as normal, including a forged or broken pass", () => {
    for (const code of [
      "POLICY_DENIED",
      "AGENT_REVOKED",
      "DELEGATION_DENIED",
      "INVALID_PROOF_OF_POSSESSION",
      "INVALID_TOKEN",
      "ACTION_MISMATCH",
      "UNKNOWN_TOOL",
      "REVOCATION_STATE_UNKNOWN_AGENT",
    ] as const) {
      expect(REFUSALS[code].severity, code).toBe("normal");
    }
    expect(refusalFor("INVALID_PROOF_OF_POSSESSION", "REPLAYED").severity).toBe("normal");
    expect(refusalFor("INVALID_PROOF_OF_POSSESSION", "SIGNATURE_INVALID").severity).toBe("normal");
  });

  it("keeps alarm for real problems", () => {
    for (const code of [
      "REVOCATION_STATE_STALE",
      "PUBLISHED_STATE_UNKNOWN",
      "UNAVAILABLE",
      "SIGNING_FAILED",
      "STATUS_ALLOCATION_FAILED",
    ] as const) {
      expect(REFUSALS[code].severity, code).toBe("alarm");
    }
  });
});

describe("refusalFor", () => {
  it("returns the code's entry", () => {
    expect(refusalFor("POLICY_DENIED")).toBe(REFUSALS.POLICY_DENIED);
  });

  it("prefers the finer reason when there is one", () => {
    expect(refusalFor("DELEGATION_DENIED", "NOT_COVERED")).toBe(
      REFUSAL_REASONS.DELEGATION_DENIED.NOT_COVERED,
    );
  });

  it("falls back to the code when the reason is unknown or free text", () => {
    expect(refusalFor("DELEGATION_DENIED", "SOMETHING_NEW")).toBe(REFUSALS.DELEGATION_DENIED);
    expect(refusalFor("INVALID_TOKEN", "EXPIRED")).toBe(REFUSALS.INVALID_TOKEN);
    expect(refusalFor("POLICY_DENIED", { not: "a string" })).toBe(REFUSALS.POLICY_DENIED);
  });

  it("does not file a reason under the wrong code", () => {
    expect(refusalFor("POLICY_DENIED", "NOT_COVERED")).toBe(REFUSALS.POLICY_DENIED);
  });

  it.each([
    ["an unknown code", "NOT_A_REAL_CODE"],
    ["an empty string", ""],
    ["a lower-case code", "policy_denied"],
    ["a name inherited from Object.prototype", "constructor"],
    ["__proto__", "__proto__"],
    ["toString", "toString"],
    ["undefined", undefined],
    ["null", null],
    ["a number", 403],
    ["an object", { code: "POLICY_DENIED" }],
    ["an oversized string", "A".repeat(1_000_000)],
  ])("treats %s as unknown, safely", (_, code) => {
    expect(refusalFor(code)).toBe(UNKNOWN_REFUSAL);
  });

  it.each(["constructor", "__proto__", "hasOwnProperty"])(
    "ignores the inherited name %s as a reason",
    (reason) => {
      expect(refusalFor("DELEGATION_DENIED", reason)).toBe(REFUSALS.DELEGATION_DENIED);
    },
  );
});

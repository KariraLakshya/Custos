import { readFile } from "node:fs/promises";
import { REFUSALS, type RefusalCode, type REFUSAL_REASONS } from "@custos/contracts";
import { describe, expect, it } from "vitest";
import type { InvokeToolError } from "./calls/invoke.js";
import type { IssueToolTokenError } from "./tokens/issue.js";

type Reasons = typeof REFUSAL_REASONS;
type ReasonOf<C extends IssueToolTokenError["code"]> = Extract<
  IssueToolTokenError,
  { code: C; reason: string }
>["reason"];

// Type-level: these lines compile only while every code has a catalogue
// entry (ADR 0022 §6). `pnpm typecheck` covers test files.
const catalogued = <C extends RefusalCode>(..._codes: C[]): true => true;
const reasonCatalogued = <C extends keyof Reasons, R extends keyof Reasons[C]>(
  ..._reasons: [C, R][]
): true => true;

describe("the vault's refusals are all in the catalogue", () => {
  it("every code a token request or a call can be refused with", () => {
    expect(catalogued<IssueToolTokenError["code"]>()).toBe(true);
    expect(catalogued<InvokeToolError["code"]>()).toBe(true);
  });

  it("every delegation and proof-of-possession reason", () => {
    expect(reasonCatalogued<"DELEGATION_DENIED", ReasonOf<"DELEGATION_DENIED">>()).toBe(true);
    expect(
      reasonCatalogued<"INVALID_PROOF_OF_POSSESSION", ReasonOf<"INVALID_PROOF_OF_POSSESSION">>(),
    ).toBe(true);
  });

  it("the check fails for a code or reason with no entry", () => {
    // @ts-expect-error not in the catalogue
    catalogued<"NOT_A_REAL_CODE">();
    // @ts-expect-error not a reason under this code
    reasonCatalogued<"DELEGATION_DENIED", "NOT_A_REAL_REASON">();
    expect(REFUSALS).not.toHaveProperty("NOT_A_REAL_CODE");
  });

  it("every code written directly into a response in server.ts", async () => {
    const source = await readFile(new URL("./server.ts", import.meta.url), "utf8");
    const written = [...source.matchAll(/error: (?:\{ code: )?"([A-Z_]+)"/g)].map((m) => m[1]);
    expect(written.length).toBeGreaterThan(0);
    for (const code of written) expect(REFUSALS, code).toHaveProperty(code as string);
  });
});

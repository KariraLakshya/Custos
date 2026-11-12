import { readFile } from "node:fs/promises";
import { REFUSALS, type RefusalCode } from "@custos/contracts";
import { describe, expect, it } from "vitest";
import type { AllocateIndexError } from "./agents/allocate.js";
import type { RevokeAgentError } from "./revoke.js";

// Type-level: these lines compile only while every code has a catalogue
// entry (ADR 0022 §6). `pnpm typecheck` covers test files.
const catalogued = <C extends RefusalCode>(..._codes: C[]): true => true;

describe("the revocation service's refusals are all in the catalogue", () => {
  it("every code a revocation or an allocation can be refused with", () => {
    expect(catalogued<RevokeAgentError["code"]>()).toBe(true);
    expect(catalogued<AllocateIndexError["code"]>()).toBe(true);
  });

  it("the check fails for a code with no entry", () => {
    // @ts-expect-error not in the catalogue
    catalogued<"NOT_A_REAL_CODE">();
    expect(REFUSALS).not.toHaveProperty("NOT_A_REAL_CODE");
  });

  it("every code written directly into a response in server.ts", async () => {
    const source = await readFile(new URL("./server.ts", import.meta.url), "utf8");
    const written = [...source.matchAll(/error: (?:\{ code: )?"([A-Z_]+)"/g)].map((m) => m[1]);
    expect(written.length).toBeGreaterThan(0);
    for (const code of written) expect(REFUSALS, code).toHaveProperty(code as string);
  });
});

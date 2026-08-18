import { describe, expect, it } from "vitest";
import { assertNever } from "./assert-never.js";

describe("assertNever", () => {
  it("throws for an unreachable case", () => {
    expect(() => assertNever("unexpected" as never)).toThrow(/Unreachable case/);
  });
});

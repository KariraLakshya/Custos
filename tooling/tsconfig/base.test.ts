import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("base tsconfig", () => {
  const config = JSON.parse(readFileSync(new URL("./base.json", import.meta.url), "utf-8"));

  it("enforces strict mode", () => {
    expect(config.compilerOptions.strict).toBe(true);
  });

  it("enforces noUncheckedIndexedAccess", () => {
    expect(config.compilerOptions.noUncheckedIndexedAccess).toBe(true);
  });
});

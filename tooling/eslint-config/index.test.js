import { describe, expect, it } from "vitest";
import { baseConfig } from "./index.js";

describe("baseConfig", () => {
  it("is a non-empty array of flat config objects", () => {
    expect(Array.isArray(baseConfig)).toBe(true);
    expect(baseConfig.length).toBeGreaterThan(0);
  });

  it("errors on explicit any", () => {
    const withRule = baseConfig.find((c) => c.rules?.["@typescript-eslint/no-explicit-any"]);
    expect(withRule.rules["@typescript-eslint/no-explicit-any"]).toBe("error");
  });
});

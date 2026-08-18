import { describe, expect, it } from "vitest";
import { err, ok } from "./result.js";

describe("Result", () => {
  it("ok() produces a success result", () => {
    const result = ok(42);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe(42);
    }
  });

  it("err() produces a failure result", () => {
    const result = err("bad");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("bad");
    }
  });
});

import { describe, expect, it } from "vitest";
import { fixedClock } from "./clock.js";

describe("fixedClock", () => {
  it("always returns the same instant", () => {
    const clock = fixedClock("2026-01-01T00:00:00.000Z");
    const first = clock.now();
    const second = clock.now();
    expect(first.toISOString()).toBe("2026-01-01T00:00:00.000Z");
    expect(second.toISOString()).toBe("2026-01-01T00:00:00.000Z");
  });

  it("returns a fresh Date instance each call", () => {
    const clock = fixedClock("2026-01-01T00:00:00.000Z");
    expect(clock.now()).not.toBe(clock.now());
  });
});

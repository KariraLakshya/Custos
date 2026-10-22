import { describe, expect, it } from "vitest";
import { createInMemoryReplayGuard } from "./replay-guard.js";

describe("createInMemoryReplayGuard", () => {
  it("accepts a proof id once and refuses it again", () => {
    const guard = createInMemoryReplayGuard();
    expect(guard.record("k", 2_000, 1_000)).toBe("fresh");
    expect(guard.record("k", 2_000, 1_001)).toBe("replayed");
  });

  it("keeps ids apart by key", () => {
    const guard = createInMemoryReplayGuard();
    expect(guard.record("issuer|agent1|jti", 2_000, 1_000)).toBe("fresh");
    expect(guard.record("issuer|agent2|jti", 2_000, 1_000)).toBe("fresh");
  });

  it("still refuses on the last millisecond a proof is live, then forgets it", () => {
    const guard = createInMemoryReplayGuard();
    guard.record("k", 2_000, 1_000);
    expect(guard.record("k", 2_000, 2_000)).toBe("replayed");
    expect(guard.record("k", 4_000, 2_001)).toBe("fresh");
  });

  it("fails closed when full of live ids, and recovers once they expire", () => {
    const guard = createInMemoryReplayGuard({ maxEntries: 2 });
    expect(guard.record("a", 2_000, 1_000)).toBe("fresh");
    expect(guard.record("b", 2_000, 1_000)).toBe("fresh");
    expect(guard.record("c", 2_000, 1_000)).toBe("full");
    // "a" and "b" are still remembered: a full guard forgot nothing.
    expect(guard.record("a", 2_000, 1_500)).toBe("replayed");
    expect(guard.record("c", 4_000, 2_001)).toBe("fresh");
  });
});

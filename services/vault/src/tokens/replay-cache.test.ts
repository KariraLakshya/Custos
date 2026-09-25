import { describe, expect, it } from "vitest";
import { createInMemoryReplayCache } from "./replay-cache.js";

describe("createInMemoryReplayCache", () => {
  it("accepts a proof id the first time and refuses it after", () => {
    const cache = createInMemoryReplayCache();

    expect(cache.record("j-1", 2_000, 1_000)).toBe("fresh");
    expect(cache.record("j-1", 2_000, 1_500)).toBe("replayed");
  });

  it("tracks ids independently", () => {
    const cache = createInMemoryReplayCache();

    expect(cache.record("j-1", 2_000, 1_000)).toBe("fresh");
    expect(cache.record("j-2", 2_000, 1_000)).toBe("fresh");
  });

  it("still refuses an id right up to its expiry", () => {
    const cache = createInMemoryReplayCache();
    cache.record("j-1", 2_000, 1_000);

    expect(cache.record("j-1", 2_000, 2_000)).toBe("replayed");
  });

  it("forgets an id once it has expired — by then the proof itself is stale", () => {
    const cache = createInMemoryReplayCache();
    cache.record("j-1", 2_000, 1_000);

    expect(cache.record("j-1", 5_000, 2_001)).toBe("fresh");
  });

  it("refuses new ids when full of unexpired ones — fails closed, never evicts a live id", () => {
    const cache = createInMemoryReplayCache({ maxEntries: 2 });
    cache.record("j-1", 10_000, 1_000);
    cache.record("j-2", 10_000, 1_000);

    expect(cache.record("j-3", 10_000, 1_000)).toBe("full");
    expect(cache.record("j-1", 10_000, 1_000)).toBe("replayed");
  });

  it("makes room again once entries expire", () => {
    const cache = createInMemoryReplayCache({ maxEntries: 2 });
    cache.record("j-1", 2_000, 1_000);
    cache.record("j-2", 2_000, 1_000);

    expect(cache.record("j-3", 9_000, 3_000)).toBe("fresh");
  });
});

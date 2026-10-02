import { mutableClock } from "@custos/testing";
import { describe, expect, it } from "vitest";
import { createLockout } from "./lockout.js";

const T0 = "2026-10-02T00:00:00.000Z";
const at = (ms: number): Date => new Date(new Date(T0).getTime() + ms);

describe("createLockout", () => {
  it("locks a source after 10 failures within 5 minutes, for 15 minutes", () => {
    const clock = mutableClock(T0);
    const lockout = createLockout({ clock });
    for (let i = 0; i < 9; i += 1) lockout.recordFailure("1.2.3.4");
    expect(lockout.isLocked("1.2.3.4")).toBe(false);
    lockout.recordFailure("1.2.3.4");
    expect(lockout.isLocked("1.2.3.4")).toBe(true);

    clock.set(at(15 * 60_000 - 1));
    expect(lockout.isLocked("1.2.3.4")).toBe(true);
    clock.set(at(15 * 60_000));
    expect(lockout.isLocked("1.2.3.4")).toBe(false);
  });

  it("locks only the failing source", () => {
    const lockout = createLockout({ clock: mutableClock(T0), maxFailures: 2 });
    lockout.recordFailure("a");
    lockout.recordFailure("a");
    expect(lockout.isLocked("a")).toBe(true);
    expect(lockout.isLocked("b")).toBe(false);
  });

  it("forgets failures older than the window", () => {
    const clock = mutableClock(T0);
    const lockout = createLockout({ clock });
    for (let i = 0; i < 9; i += 1) lockout.recordFailure("a");
    clock.set(at(5 * 60_000));
    lockout.recordFailure("a");
    expect(lockout.isLocked("a")).toBe(false);
  });

  it("starts a fresh count once a lock has expired", () => {
    const clock = mutableClock(T0);
    const lockout = createLockout({ clock, maxFailures: 2, windowMs: 1_000, lockMs: 10_000 });
    lockout.recordFailure("a");
    lockout.recordFailure("a");
    clock.set(at(10_000));
    expect(lockout.isLocked("a")).toBe(false);
    lockout.recordFailure("a");
    expect(lockout.isLocked("a")).toBe(false);
    lockout.recordFailure("a");
    expect(lockout.isLocked("a")).toBe(true);
  });

  it("stays bounded, dropping the least recently failed source", () => {
    const lockout = createLockout({ clock: mutableClock(T0), maxFailures: 1, maxSources: 2 });
    lockout.recordFailure("a");
    lockout.recordFailure("b");
    lockout.recordFailure("a"); // a is now the most recent
    lockout.recordFailure("c"); // evicts b
    expect(lockout.isLocked("a")).toBe(true);
    expect(lockout.isLocked("b")).toBe(false);
    expect(lockout.isLocked("c")).toBe(true);
  });
});

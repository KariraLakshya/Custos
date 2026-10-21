import { readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isRevoked, verifyForeignStatusList, type StatusAnchor } from "@custos/core";
import { afterEach, describe, expect, it } from "vitest";
import { realFileOps, type FileOps } from "./files.js";
import { appendJournal } from "./journal.js";
import {
  hasBaseline,
  publishOnce,
  publisherIdentity,
  publisherPaths,
  runPublisher,
  type PublishResult,
} from "./publish.js";
import { revokeFromPublisher } from "./revoke.js";
import { INIT, SEED, keyFor, makeKit, readList, T0, type Kit } from "./testkit.js";

const kits: Kit[] = [];
async function kit(...args: Parameters<typeof makeKit>): Promise<Kit> {
  const made = await makeKit(...args);
  kits.push(made);
  return made;
}
afterEach(async () => {
  await Promise.all(kits.splice(0).map((made) => made.cleanup()));
});

async function anchorFor(k: Kit): Promise<StatusAnchor> {
  const identity = await publisherIdentity(k.config, k.deps);
  return {
    statusIssuerDid: identity.did,
    statusIssuerPublicKey: identity.publicKey,
    statusListId: identity.listId,
    maxStatusAgeSeconds: k.config.validitySeconds,
  };
}

/** The list at `path`, verified the way a foreign verifier would (fresh required). */
async function verifiedList(k: Kit, path = k.out) {
  const result = await verifyForeignStatusList({
    credential: await readList(path),
    anchor: await anchorFor(k),
    now: k.clock.now(),
    maxClockSkewSeconds: 5,
  });
  if (!result.ok) throw new Error(`published list rejected: ${result.error.code}`);
  return result.value;
}

const bit = (list: Uint8Array, index: number): boolean => {
  const result = isRevoked(list, index);
  return result.ok && result.value;
};

const ok = (result: PublishResult) => {
  if (!result.ok) throw new Error(`expected a publish, got ${result.error.code}`);
  return result.value;
};

async function revokeIndex(k: Kit, index: number) {
  return revokeFromPublisher(k.config, k.deps, {
    target: { index: String(index), confirmIndex: String(index) },
    operator: "lakshya",
    reason: "test",
  });
}

describe("init and stamping", () => {
  it("starts a publisher: an empty list that a foreign verifier accepts, with the promised window", async () => {
    const k = await kit();
    const outcome = ok(await publishOnce(k.config, k.deps, INIT));
    expect(outcome.revokedCount).toBe(0);
    expect(outcome.validFrom).toEqual(T0);
    expect(outcome.validUntil.getTime() - outcome.validFrom.getTime()).toBe(3600_000);

    const view = await verifiedList(k);
    expect(view.notAfter.toISOString()).toBe("2026-10-21T11:00:00.000Z");
    expect(await readFile(publisherPaths(k.config).journal, "utf8")).toBe(""); // created, empty
    expect((await readList(publisherPaths(k.config).state)).validFrom).toBe(T0.toISOString()); // state is the same list
  });

  it("stamps: the same revocations with a fresh validFrom and validUntil", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 41);
    k.clock.advance(1200_000);
    const stamped = ok(await publishOnce(k.config, k.deps));
    expect(stamped.validFrom.toISOString()).toBe("2026-10-21T10:20:00.000Z");
    expect(stamped.validUntil.toISOString()).toBe("2026-10-21T11:20:00.000Z");
    const view = await verifiedList(k);
    expect(bit(view.list, 41)).toBe(true);
    expect(view.validFrom.toISOString()).toBe("2026-10-21T10:20:00.000Z");
  });

  it("publishes a revocation in the same call that records it", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    const revoked = await revokeIndex(k, 7);
    expect(revoked).toMatchObject({
      ok: true,
      value: { index: 7, published: { revokedCount: 1 } },
    });
    expect(bit((await verifiedList(k)).list, 7)).toBe(true);
    const journal = (await readFile(publisherPaths(k.config).journal, "utf8")).trim().split("\n");
    expect(JSON.parse(journal[0]!)).toMatchObject({
      index: 7,
      operator: "lakshya",
      reason: "test",
    });
  });
});

describe("a lost or rolled-back state cannot lose a revocation", () => {
  async function withRevocations() {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 3);
    await revokeIndex(k, 90);
    return k;
  }

  it("rebuilds from the journal when the state and the published copy are both deleted", async () => {
    const k = await withRevocations();
    await rm(publisherPaths(k.config).state);
    await rm(k.out);
    k.clock.advance(60_000);
    ok(await publishOnce(k.config, k.deps));
    const view = await verifiedList(k);
    expect([3, 90].map((i) => bit(view.list, i))).toEqual([true, true]);
  });

  it("restores a revocation that an older genuinely-signed state is missing, and re-stamps with a fresh time", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 3);
    const olderCopy = await readFile(k.out, "utf8"); // a real signed list that has only index 3
    await revokeIndex(k, 90);
    await writeFile(publisherPaths(k.config).state, olderCopy); // roll the state back
    await writeFile(k.out, olderCopy); // and the published copy

    k.clock.advance(30_000);
    ok(await publishOnce(k.config, k.deps));
    const view = await verifiedList(k);
    expect(bit(view.list, 90)).toBe(true); // the journal brought it back
    expect(view.validFrom.toISOString()).toBe("2026-10-21T10:00:30.000Z");
  });

  it("rebuilds from the state or published copy when the journal is deleted", async () => {
    const k = await withRevocations();
    await rm(publisherPaths(k.config).journal);
    k.clock.advance(60_000);
    ok(await publishOnce(k.config, k.deps));
    const view = await verifiedList(k);
    expect([3, 90].map((i) => bit(view.list, i))).toEqual([true, true]);
  });

  it("rebuilds from the last signed state alone when the journal and the published copy are both gone", async () => {
    const k = await withRevocations();
    await rm(publisherPaths(k.config).journal);
    await rm(k.out);
    k.clock.advance(60_000);
    ok(await publishOnce(k.config, k.deps));
    const view = await verifiedList(k);
    expect([3, 90].map((i) => bit(view.list, i))).toEqual([true, true]);
  });

  it("rebuilds from the published copy alone when the journal and the state are both gone", async () => {
    const k = await withRevocations();
    await rm(publisherPaths(k.config).journal);
    await rm(publisherPaths(k.config).state);
    k.clock.advance(60_000);
    ok(await publishOnce(k.config, k.deps));
    const view = await verifiedList(k);
    expect([3, 90].map((i) => bit(view.list, i))).toEqual([true, true]);
  });

  it("rebuilds from the host's copy when the journal, the state and the local copy are all gone", async () => {
    const k = await withRevocations();
    const hostCopy = JSON.parse(await readFile(k.out, "utf8")) as unknown;
    await rm(publisherPaths(k.config).journal);
    await rm(publisherPaths(k.config).state);
    await rm(k.out);
    const recovering = { ...k, deps: { ...k.deps, fetchHost: async () => hostCopy } };
    ok(await publishOnce(k.config, recovering.deps));
    const view = await verifiedList(k);
    expect([3, 90].map((i) => bit(view.list, i))).toEqual([true, true]);
  });

  it("refuses to publish from nothing: no journal, no state, no host copy, and no init", async () => {
    const k = await kit();
    expect(await publishOnce(k.config, k.deps)).toEqual({
      ok: false,
      error: { code: "NO_BASELINE" },
    });
    await expect(readFile(k.out)).rejects.toThrow(); // nothing was written
    expect(await hasBaseline(k.config, k.deps)).toEqual({ ok: true, value: false });
  });

  it("refuses to revoke before the publisher has been initialised, and writes nothing", async () => {
    const k = await kit();
    expect(await revokeIndex(k, 5)).toEqual({ ok: false, error: { code: "NO_BASELINE" } });
    await expect(readFile(publisherPaths(k.config).journal)).rejects.toThrow();
  });
});

describe("a damaged journal is never skipped over", () => {
  it("ignores a cut-off final line with a warning, and publishes what it has", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 5);
    await writeFile(
      publisherPaths(k.config).journal,
      `${await readFile(publisherPaths(k.config).journal, "utf8")}{"index":9,"at":"2026`,
    );
    const outcome = ok(await publishOnce(k.config, k.deps));
    expect(outcome.warnings.join(" ")).toContain("cut-off");
    expect(bit((await verifiedList(k)).list, 5)).toBe(true);
  });

  it("refuses to publish at all when a line in the middle is damaged, leaving the last list alone", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 5);
    const before = await readFile(k.out, "utf8");
    await writeFile(publisherPaths(k.config).journal, "garbage\n{}\n");
    const result = await publishOnce(k.config, k.deps);
    expect(result).toMatchObject({ ok: false, error: { code: "JOURNAL_CORRUPT", line: 1 } });
    expect(await readFile(k.out, "utf8")).toBe(before);
  });
});

describe("init cannot start from nothing by accident", () => {
  it("is refused unless it was told where to look for a published list, or told there is none", async () => {
    const k = await kit();
    expect(await publishOnce(k.config, k.deps, { init: true })).toEqual({
      ok: false,
      error: { code: "INIT_NEEDS_HOST" },
    });
    await expect(readFile(publisherPaths(k.config).journal)).rejects.toThrow();
  });

  it("proceeds when the host is asked and says it has no list", async () => {
    const k = await kit({}, { fetchHost: async () => undefined });
    ok(await publishOnce(k.config, k.deps, { init: true }));
  });

  it("proceeds when the operator states that nothing has ever been published", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
  });

  it("is not satisfied by an acknowledgement of `false`", async () => {
    const k = await kit();
    expect(
      await publishOnce(k.config, k.deps, { init: true, acknowledgeNoPublishedList: false }),
    ).toEqual({
      ok: false,
      error: { code: "INIT_NEEDS_HOST" },
    });
  });
});

describe("init is refused whenever it could replace earlier revocations", () => {
  it("when the journal already exists", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    expect(await publishOnce(k.config, k.deps, INIT)).toMatchObject({
      ok: false,
      error: { code: "ALREADY_INITIALISED" },
    });
  });

  it("when a journal exists, even if no list is served anywhere", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 12);
    await rm(publisherPaths(k.config).state);
    await rm(k.out);
    expect(await publishOnce(k.config, k.deps, INIT)).toMatchObject({
      ok: false,
      error: { code: "ALREADY_INITIALISED", where: expect.stringContaining("journal.jsonl") },
    });
    // The journal still holds the revocation, so a normal publish restores it.
    ok(await publishOnce(k.config, k.deps));
    expect(bit((await verifiedList(k)).list, 12)).toBe(true);
  });

  it("when a list signed by this key is already served, even with the journal gone", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 12);
    await rm(publisherPaths(k.config).journal);
    await rm(publisherPaths(k.config).state);
    expect(await publishOnce(k.config, k.deps, INIT)).toMatchObject({
      ok: false,
      error: { code: "ALREADY_INITIALISED", where: expect.stringContaining("already served") },
    });
    expect(bit((await verifiedList(k)).list, 12)).toBe(true); // untouched
  });

  it("when the host serves a list signed by this key", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    const hostCopy = JSON.parse(await readFile(k.out, "utf8")) as unknown;
    const fresh = await kit({}, { fetchHost: async () => hostCopy });
    expect(
      await publishOnce(fresh.config, { ...fresh.deps, fetchHost: async () => hostCopy }, INIT),
    ).toMatchObject({
      ok: false,
      error: { code: "ALREADY_INITIALISED" },
    });
  });

  it("when the host cannot be read, because it might be serving one", async () => {
    const k = await kit(
      {},
      {
        fetchHost: async () => {
          throw new Error("connect ECONNREFUSED");
        },
      },
    );
    expect(await publishOnce(k.config, k.deps, INIT)).toMatchObject({
      ok: false,
      error: { code: "HOST_UNREACHABLE", reason: "connect ECONNREFUSED" },
    });
    await expect(readFile(publisherPaths(k.config).journal)).rejects.toThrow();
  });

  it("but proceeds when the host answers that it has no list yet", async () => {
    const k = await kit({}, { fetchHost: async () => undefined });
    ok(await publishOnce(k.config, k.deps, INIT));
  });
});

describe("only lists signed by this publisher's key are merged", () => {
  it("refuses to publish, and changes nothing, when a list for this identity is signed by a different key", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 4);
    const before = await readFile(k.out, "utf8");
    // The same identity, started again with the wrong seed.
    const wrongSeed = { ...k.deps, ...keyFor("22".repeat(32)) };
    k.clock.advance(60_000);

    // Both the state and the published list carry the good list; the state is read first.
    expect(await publishOnce(k.config, wrongSeed)).toMatchObject({
      ok: false,
      error: { code: "KEY_MISMATCH", where: "state" },
    });
    expect(await readFile(k.out, "utf8")).toBe(before); // the good list was not replaced

    // Each copy is checked on its own: the published list alone is enough to refuse...
    await rm(publisherPaths(k.config).state);
    expect(await publishOnce(k.config, wrongSeed)).toMatchObject({
      ok: false,
      error: { code: "KEY_MISMATCH", where: "published" },
    });
    expect(await readFile(k.out, "utf8")).toBe(before);

    // ...and so is the state alone...
    await writeFile(publisherPaths(k.config).state, before);
    await rm(k.out);
    expect(await publishOnce(k.config, wrongSeed)).toMatchObject({
      ok: false,
      error: { code: "KEY_MISMATCH", where: "state" },
    });

    // ...and init is refused too, rather than starting an empty list over it.
    await rm(publisherPaths(k.config).journal);
    expect(await publishOnce(k.config, wrongSeed, INIT)).toMatchObject({
      ok: false,
      error: { code: "KEY_MISMATCH" },
    });
    // With the right key everything is still there.
    ok(await publishOnce(k.config, k.deps));
    expect(bit((await verifiedList(k)).list, 4)).toBe(true);
  });

  it("refuses when the host's list for this identity is signed by a different key", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    const hostCopy = JSON.parse(await readFile(k.out, "utf8")) as unknown;
    await rm(k.dir, { recursive: true, force: true });
    const other = await kit();
    const result = await publishOnce(other.config, {
      ...other.deps,
      ...keyFor("33".repeat(32)),
      fetchHost: async () => hostCopy,
    });
    expect(result).toMatchObject({ ok: false, error: { code: "KEY_MISMATCH", where: "host" } });
  });

  it("ignores, with a warning, a list that belongs to a different identity", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    const elsewhere = await kit({ domain: "other.example" });
    ok(await publishOnce(elsewhere.config, elsewhere.deps, INIT));
    await writeFile(k.out, await readFile(elsewhere.out, "utf8"));
    const outcome = ok(await publishOnce(k.config, k.deps));
    expect(outcome.warnings.join(" ")).toContain("LIST_WRONG_ISSUER");
  });

  it("ignores a file that is not JSON, with a warning", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await writeFile(publisherPaths(k.config).state, "{ not json");
    const outcome = ok(await publishOnce(k.config, k.deps));
    expect(outcome.warnings.join(" | ")).toContain("not readable JSON");
  });
});

describe("A's database is one input to the union", () => {
  it("adds the indexes A's database holds as revoked", async () => {
    const k = await kit({}, { readDatabaseIndexes: async () => [4, 600] });
    ok(await publishOnce(k.config, k.deps, INIT));
    const view = await verifiedList(k);
    expect([4, 600, 5].map((i) => bit(view.list, i))).toEqual([true, true, false]);
  });

  it("carries on, with a warning, when A's database cannot be read", async () => {
    const k = await kit(
      {},
      {
        readDatabaseIndexes: async () => {
          throw new Error("connect ECONNREFUSED");
        },
      },
    );
    const outcome = ok(await publishOnce(k.config, k.deps, INIT));
    expect(outcome.warnings.join(" ")).toContain("left out");
  });

  it("drops an index that is out of range instead of building a huge list", async () => {
    const k = await kit({}, { readDatabaseIndexes: async () => [5, 16 * 1024 * 1024 * 8, -1] });
    const outcome = ok(await publishOnce(k.config, k.deps, INIT));
    expect(outcome.warnings.join(" ")).toContain("out of range");
    expect(outcome.revokedCount).toBe(1);
  });
});

describe("a write that fails is never reported as published", () => {
  const refuseRenameTo = (suffix: string): FileOps => ({
    ...realFileOps,
    rename: async (from, to) => {
      if (to.endsWith(suffix))
        throw Object.assign(new Error("EBUSY: resource busy"), { code: "EBUSY" });
      await realFileOps.rename(from, to);
    },
  });

  it("reports WRITE_FAILED, leaves the previous list in place, and removes the temporary file", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 8);
    const before = await readFile(k.out, "utf8");
    k.clock.advance(60_000);
    const result = await publishOnce(k.config, {
      ...k.deps,
      fileOps: refuseRenameTo("status.json"),
      sleep: async () => undefined,
    });
    expect(result).toMatchObject({ ok: false, error: { code: "WRITE_FAILED" } });
    expect(await readFile(k.out, "utf8")).toBe(before);
    expect((await readdir(dirname(k.out))).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });

  it("treats a failed state refresh as a warning: the list was published", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    k.clock.advance(60_000);
    const outcome = ok(
      await publishOnce(k.config, {
        ...k.deps,
        fileOps: refuseRenameTo("state.json"),
        sleep: async () => undefined,
      }),
    );
    expect(outcome.warnings.join(" ")).toContain("state file was not refreshed");
    expect((await verifiedList(k)).validFrom.toISOString()).toBe("2026-10-21T10:01:00.000Z");
  });

  it("records a revocation even when it cannot be published, and the next publish carries it", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    const result = await revokeFromPublisher(
      k.config,
      { ...k.deps, fileOps: refuseRenameTo("status.json"), sleep: async () => undefined },
      { target: { index: "21", confirmIndex: "21" }, operator: "lakshya", reason: "leak" },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { code: "NOT_PUBLISHED", reason: { code: "WRITE_FAILED" } },
    });
    expect(bit((await verifiedList(k)).list, 21)).toBe(false);
    k.clock.advance(60_000);
    ok(await publishOnce(k.config, k.deps));
    expect(bit((await verifiedList(k)).list, 21)).toBe(true);
  });
});

describe("one writer at a time", () => {
  it("a revocation made during a publish is in the published list afterwards, never lost", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));

    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    let calls = 0;
    const slowFirst = {
      ...k.deps,
      sleep: (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, Math.min(ms, 5))),
      fetchHost: async () => {
        calls += 1;
        if (calls === 1) await gate; // the first publish is stuck inside the lock, having already read the journal
        return undefined;
      },
    };

    const cycle = publishOnce(k.config, slowFirst);
    await new Promise((resolve) => setTimeout(resolve, 40));
    const revoking = revokeFromPublisher(k.config, slowFirst, {
      target: { index: "55", confirmIndex: "55" },
      operator: "lakshya",
      reason: "during a cycle",
    });
    await new Promise((resolve) => setTimeout(resolve, 40));
    release();
    const [cycleResult, revokeResult] = await Promise.all([cycle, revoking]);

    expect(cycleResult.ok).toBe(true);
    expect(revokeResult.ok).toBe(true);
    expect(bit((await verifiedList(k)).list, 55)).toBe(true);
  });

  it("gives up with LOCK_TIMEOUT rather than wait forever for a lock someone holds", async () => {
    const k = await kit({ lockWaitMs: 100 });
    ok(await publishOnce(k.config, k.deps, INIT));
    await writeFile(publisherPaths(k.config).lock, "{}");
    // The injected clock only moves when something sleeps, as a real one moves while it waits.
    const result = await publishOnce(k.config, {
      ...k.deps,
      sleep: async (ms) => k.clock.advance(ms),
    });
    expect(result).toEqual({ ok: false, error: { code: "LOCK_TIMEOUT" } });
  });
});

describe("a publish that has lost its lock writes nothing", () => {
  it("returns LOCK_LOST and leaves the published list as it was", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 6);
    const before = await readFile(k.out, "utf8");
    k.clock.advance(60_000);
    const slow = {
      ...k.deps,
      fetchHost: async () => {
        // While this cycle is working, another process takes the lock over.
        await writeFile(publisherPaths(k.config).lock, JSON.stringify({ token: "someone-else" }));
        return undefined;
      },
    };
    expect(await publishOnce(k.config, slow)).toEqual({ ok: false, error: { code: "LOCK_LOST" } });
    expect(await readFile(k.out, "utf8")).toBe(before);
  });
});

describe("runPublisher", () => {
  it("re-signs on every interval until stopped, and reports each cycle", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    const controller = new AbortController();
    const cycles: PublishResult[] = [];
    const sleeps: number[] = [];
    const deps = {
      ...k.deps,
      sleep: async (ms: number) => {
        sleeps.push(ms);
        k.clock.advance(ms);
        if (sleeps.length === 3) controller.abort();
      },
    };
    await runPublisher(k.config, deps, {
      signal: controller.signal,
      onCycle: (r) => cycles.push(r),
    });
    expect(cycles.map((r) => r.ok)).toEqual([true, true, true]);
    expect(sleeps).toEqual([1200_000, 1200_000, 1200_000]);
    expect(cycles.map((r) => (r.ok ? r.value.validFrom.toISOString() : ""))).toEqual([
      "2026-10-21T10:00:00.000Z",
      "2026-10-21T10:20:00.000Z",
      "2026-10-21T10:40:00.000Z",
    ]);
  });

  it("carries on after a failure that may pass, and stops at one that needs a person", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    const controller = new AbortController();
    let renames = 0;
    const flaky: FileOps = {
      ...realFileOps,
      rename: async (from, to) => {
        renames += 1;
        if (renames <= 6) throw Object.assign(new Error("EBUSY"), { code: "EBUSY" }); // a whole first cycle fails
        await realFileOps.rename(from, to);
      },
    };
    const results: PublishResult[] = [];
    const last = await runPublisher(
      k.config,
      {
        ...k.deps,
        fileOps: flaky,
        sleep: async () => {
          if (results.length === 2) {
            await writeFile(publisherPaths(k.config).journal, "garbage\n{}\n"); // now it needs a person
          }
        },
      },
      { signal: controller.signal, onCycle: (r) => results.push(r) },
    );
    expect(results.map((r) => (r.ok ? "ok" : r.error.code))).toEqual([
      "WRITE_FAILED",
      "ok",
      "JOURNAL_CORRUPT",
    ]);
    expect(last).toMatchObject({ ok: false, error: { code: "JOURNAL_CORRUPT" } });
  });

  it("stops straight away when there is nothing to build on", async () => {
    const k = await kit();
    const results: PublishResult[] = [];
    const last = await runPublisher(k.config, k.deps, {
      signal: new AbortController().signal,
      onCycle: (r) => results.push(r),
    });
    expect(last).toEqual({ ok: false, error: { code: "NO_BASELINE" } });
    expect(results).toHaveLength(1);
  });

  it("stops promptly when told to stop in the middle of a cycle, not a whole stamp interval later", async () => {
    const k = await kit({ stampSeconds: 3000 });
    ok(await publishOnce(k.config, k.deps, INIT));
    const controller = new AbortController();
    const started = Date.now();
    // The stop signal arrives during the cycle, before the loop has begun to wait.
    const stopping = {
      ...k.deps,
      fetchHost: async () => {
        controller.abort();
        return undefined;
      },
    };
    await runPublisher(k.config, stopping, { signal: controller.signal, onCycle: () => undefined });
    expect(Date.now() - started).toBeLessThan(2_000);
  }, 5_000);

  it("uses a real timer that an abort cuts short", async () => {
    const k = await kit({ stampSeconds: 3000 });
    ok(await publishOnce(k.config, k.deps, INIT));
    const controller = new AbortController();
    const started = Date.now();
    setTimeout(() => controller.abort(), 50);
    await runPublisher(k.config, k.deps, { signal: controller.signal, onCycle: () => undefined });
    expect(Date.now() - started).toBeLessThan(2_000);
  });
});

describe("the publisher's key", () => {
  it("never appears in the journal, the state, or the published list", async () => {
    const k = await kit();
    ok(await publishOnce(k.config, k.deps, INIT));
    await revokeIndex(k, 9);
    await appendJournal(publisherPaths(k.config).journal, {
      index: 10,
      at: T0.toISOString(),
      operator: "lakshya",
      reason: "ok",
    });
    for (const path of [publisherPaths(k.config).journal, publisherPaths(k.config).state, k.out]) {
      expect(await readFile(path, "utf8")).not.toContain(SEED);
    }
  });
});

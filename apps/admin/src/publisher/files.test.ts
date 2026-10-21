import { mkdir, mkdtemp, readdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { realFileOps, WriteFailedError, withLock, writeFileAtomic, type FileOps } from "./files.js";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "custos-files-"));
});
afterEach(() => rm(dir, { recursive: true, force: true }));

const noSleep = async () => undefined;
const failing = (code: string): NodeJS.ErrnoException => Object.assign(new Error(code), { code });

function opsRenaming(
  behaviour: (attempt: number) => Error | undefined,
): FileOps & { renames: number } {
  const ops = {
    renames: 0,
    writeSynced: realFileOps.writeSynced,
    remove: realFileOps.remove,
    async rename(from: string, to: string) {
      ops.renames += 1;
      const error = behaviour(ops.renames);
      if (error !== undefined) throw error;
      await realFileOps.rename(from, to);
    },
  };
  return ops;
}

describe("writeFileAtomic", () => {
  it("writes the file, creating its directory, and leaves no temporary file behind", async () => {
    const target = join(dir, "site", "status.json");
    await writeFileAtomic(target, "hello\n");
    expect(await readFile(target, "utf8")).toBe("hello\n");
    expect(await readdir(join(dir, "site"))).toEqual(["status.json"]);
  });

  it("replaces an existing file whole", async () => {
    const target = join(dir, "status.json");
    await writeFile(target, "old");
    await writeFileAtomic(target, "new");
    expect(await readFile(target, "utf8")).toBe("new");
  });

  it("retries a rename that Windows refuses while another process holds the file, then succeeds", async () => {
    const target = join(dir, "status.json");
    const ops = opsRenaming((attempt) =>
      attempt < 4 ? failing(["EPERM", "EBUSY", "EACCES"][attempt - 1]!) : undefined,
    );
    const delays: number[] = [];
    await writeFileAtomic(target, "data", { ops, sleep: async (ms) => void delays.push(ms) });
    expect(ops.renames).toBe(4);
    expect(delays).toEqual([25, 50, 100]); // bounded exponential backoff
    expect(await readFile(target, "utf8")).toBe("data");
  });

  it("gives up after the bounded number of attempts, leaves the target untouched, and says it failed", async () => {
    const target = join(dir, "status.json");
    await writeFile(target, "previous list");
    const ops = opsRenaming(() => failing("EBUSY"));
    await expect(
      writeFileAtomic(target, "new", { ops, sleep: noSleep, attempts: 3 }),
    ).rejects.toBeInstanceOf(WriteFailedError);
    expect(ops.renames).toBe(3);
    expect(await readFile(target, "utf8")).toBe("previous list");
    expect(await readdir(dir)).toEqual(["status.json"]); // the temporary file was removed
  });

  it("does not retry an error that retrying cannot fix", async () => {
    const ops = opsRenaming(() => failing("ENOSPC"));
    await expect(
      writeFileAtomic(join(dir, "x.json"), "d", { ops, sleep: noSleep }),
    ).rejects.toThrow("ENOSPC");
    expect(ops.renames).toBe(1);
  });

  it("reports a failure to write the temporary file", async () => {
    const ops: FileOps = {
      ...realFileOps,
      writeSynced: async () => {
        throw failing("EROFS");
      },
    };
    await expect(writeFileAtomic(join(dir, "x.json"), "d", { ops })).rejects.toBeInstanceOf(
      WriteFailedError,
    );
  });

  it("succeeds once a real handle that was holding the file is released during the retries", async () => {
    const target = join(dir, "status.json");
    await writeFile(target, "v1");
    const { open } = await import("node:fs/promises");
    const held = await open(target, "r");
    // A static file server holds the file only while it serves a request.
    setTimeout(() => void held.close(), 60);
    await writeFileAtomic(target, "v2", { attempts: 8, baseDelayMs: 20 });
    expect(await readFile(target, "utf8")).toBe("v2");
  });

  // Windows refuses to rename over a file that stays open; elsewhere the rename just works.
  it.skipIf(process.platform !== "win32")(
    "on Windows, a file held open throughout is reported as NOT written, and left as it was",
    async () => {
      const target = join(dir, "status.json");
      await writeFile(target, "v1");
      const { open } = await import("node:fs/promises");
      const held = await open(target, "r");
      try {
        await expect(
          writeFileAtomic(target, "v2", { attempts: 3, baseDelayMs: 5 }),
        ).rejects.toBeInstanceOf(WriteFailedError);
        expect(await readFile(target, "utf8")).toBe("v1");
        expect(await readdir(dir)).toEqual(["status.json"]);
      } finally {
        await held.close();
      }
    },
  );
});

describe("withLock", () => {
  const options = (now: () => Date, extra: Record<string, number> = {}) => ({
    now,
    sleep: noSleep,
    staleAfterMs: 60_000,
    waitMs: 1_000,
    ...extra,
  });

  it("runs the work, removes the lock afterwards, and returns the work's value", async () => {
    const lock = join(dir, "p", "publisher.lock");
    const result = await withLock(
      lock,
      options(() => new Date()),
      async () => 42,
    );
    expect(result).toEqual({ ok: true, value: 42 });
    await expect(stat(lock)).rejects.toThrow();
  });

  it("removes the lock even when the work throws", async () => {
    const lock = join(dir, "publisher.lock");
    await expect(
      withLock(
        lock,
        options(() => new Date()),
        async () => Promise.reject(new Error("boom")),
      ),
    ).rejects.toThrow("boom");
    await expect(stat(lock)).rejects.toThrow();
  });

  it("makes two callers take turns", async () => {
    const lock = join(dir, "publisher.lock");
    const order: string[] = [];
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const real = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
    const opts = {
      now: () => new Date(),
      sleep: real,
      staleAfterMs: 60_000,
      waitMs: 5_000,
      pollMs: 5,
    };
    const first = withLock(lock, opts, async () => {
      order.push("first-start");
      await gate;
      order.push("first-end");
    });
    await real(30);
    const second = withLock(lock, opts, async () => void order.push("second"));
    await real(50);
    expect(order).toEqual(["first-start"]); // the second is waiting
    release();
    await Promise.all([first, second]);
    expect(order).toEqual(["first-start", "first-end", "second"]);
  });

  it("gives up waiting for a lock that is held and recent", async () => {
    const lock = join(dir, "publisher.lock");
    await writeFile(lock, "{}");
    let t = Date.now();
    const result = await withLock(
      lock,
      { now: () => new Date((t += 600)), sleep: noSleep, staleAfterMs: 60_000, waitMs: 1_000 },
      async () => 1,
    );
    expect(result).toEqual({ ok: false, error: { code: "LOCK_TIMEOUT", path: lock } });
    expect(await readFile(lock, "utf8")).toBe("{}"); // someone else's lock is left alone
  });

  it("takes over a lock left by a process that died, once it is older than the stale limit", async () => {
    const lock = join(dir, "publisher.lock");
    await writeFile(lock, "{}");
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(lock, old, old);
    const result = await withLock(
      lock,
      options(() => new Date(), { staleAfterMs: 60_000 }),
      async () => "took over",
    );
    expect(result).toEqual({ ok: true, value: "took over" });
  });

  it("does not take over a lock that is merely old by this machine's other clocks but within the stale limit", async () => {
    const lock = join(dir, "publisher.lock");
    await mkdir(dir, { recursive: true });
    await writeFile(lock, "{}");
    let t = Date.now();
    const result = await withLock(
      lock,
      { now: () => new Date((t += 100)), sleep: noSleep, staleAfterMs: 3_600_000, waitMs: 500 },
      async () => 1,
    );
    expect(result.ok).toBe(false);
  });
});

describe("withLock: the lock belongs to whoever took it", () => {
  const options = {
    now: () => new Date(),
    sleep: async () => undefined,
    staleAfterMs: 60_000,
    waitMs: 1_000,
  };

  it("does not delete a lock that another holder has taken over", async () => {
    const lock = join(dir, "publisher.lock");
    const result = await withLock(lock, options, async () => {
      // A second process judged this lock stale and took it over.
      await writeFile(
        lock,
        JSON.stringify({ pid: 1, at: new Date().toISOString(), token: "someone-else" }),
      );
    });
    expect(result.ok).toBe(true);
    expect(JSON.parse(await readFile(lock, "utf8"))).toMatchObject({ token: "someone-else" });
  });

  it("tells the work whether it still holds the lock", async () => {
    const lock = join(dir, "publisher.lock");
    const seen: boolean[] = [];
    await withLock(lock, options, async (held) => {
      seen.push(await held.stillHeld());
      await writeFile(lock, JSON.stringify({ token: "someone-else" }));
      seen.push(await held.stillHeld());
      await rm(lock);
      seen.push(await held.stillHeld());
    });
    expect(seen).toEqual([true, false, false]);
  });

  it("treats a lock file it cannot read as not held", async () => {
    const lock = join(dir, "publisher.lock");
    const seen: boolean[] = [];
    await withLock(lock, options, async (held) => {
      await writeFile(lock, "not json");
      seen.push(await held.stillHeld());
    });
    expect(seen).toEqual([false]);
  });
});

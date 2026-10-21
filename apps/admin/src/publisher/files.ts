import { randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename, rm, stat } from "node:fs/promises";
import { dirname } from "node:path";

/** Filesystem operations the publisher needs, injectable so failures can be tested. */
export interface FileOps {
  writeSynced(path: string, contents: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  remove(path: string): Promise<void>;
}

export const realFileOps: FileOps = {
  async writeSynced(path, contents) {
    const handle = await open(path, "w");
    try {
      await handle.write(contents);
      await handle.sync();
    } finally {
      await handle.close();
    }
  },
  rename: (from, to) => rename(from, to),
  remove: (path) => rm(path, { force: true }),
};

const RETRYABLE = new Set(["EPERM", "EBUSY", "EACCES"]);

export class WriteFailedError extends Error {
  constructor(
    readonly path: string,
    reason: string,
  ) {
    super(`could not write ${path}: ${reason}`);
    this.name = "WriteFailedError";
  }
}

/**
 * Writes to a temporary file in the same directory, fsyncs it, then renames it
 * over the target, so a reader never sees half a list. Windows refuses a rename
 * over a file another process has open (EPERM/EBUSY/EACCES), which a static file
 * server can cause; those are retried a bounded number of times with backoff.
 * A write that still fails is an error: it is never reported as published.
 */
export async function writeFileAtomic(
  target: string,
  contents: string,
  options: {
    readonly ops?: FileOps;
    readonly sleep?: (ms: number) => Promise<void>;
    readonly attempts?: number;
    readonly baseDelayMs?: number;
  } = {},
): Promise<void> {
  const ops = options.ops ?? realFileOps;
  const sleep =
    options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const attempts = options.attempts ?? 6;
  const baseDelayMs = options.baseDelayMs ?? 25;
  const temporary = `${target}.${randomBytes(6).toString("hex")}.tmp`;

  try {
    await mkdir(dirname(target), { recursive: true });
    await ops.writeSynced(temporary, contents);
    for (let attempt = 0; ; attempt += 1) {
      try {
        await ops.rename(temporary, target);
        return;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === undefined || !RETRYABLE.has(code) || attempt + 1 >= attempts) throw error;
        await sleep(baseDelayMs * 2 ** attempt);
      }
    }
  } catch (error) {
    await ops.remove(temporary).catch(() => undefined);
    if (error instanceof WriteFailedError) throw error;
    throw new WriteFailedError(target, error instanceof Error ? error.message : String(error));
  }
}

export interface LockOptions {
  readonly now: () => Date;
  readonly sleep?: (ms: number) => Promise<void>;
  /** A lock older than this was left by a process that died; it is taken over. */
  readonly staleAfterMs: number;
  /** How long to wait for a lock someone else holds before giving up. */
  readonly waitMs: number;
  readonly pollMs?: number;
}

export type LockError = { readonly code: "LOCK_TIMEOUT"; readonly path: string };

/** What the work running under a lock can ask of it. */
export interface HeldLock {
  /**
   * True only while the lock file still carries this holder's token. If another
   * process judged the lock stale and took it over, the work must stop writing.
   */
  stillHeld(): Promise<boolean>;
}

async function tokenIn(path: string): Promise<string | undefined> {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as { token?: unknown };
    return typeof parsed.token === "string" ? parsed.token : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Runs `work` while holding an exclusive lock file, so two publishes (the
 * stamping loop and a `revoke`) never read, build and write at the same time.
 * Anything else in the same directory is left alone.
 */
export async function withLock<T>(
  path: string,
  options: LockOptions,
  work: (lock: HeldLock) => Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false; error: LockError }> {
  const sleep =
    options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const pollMs = options.pollMs ?? 50;
  const deadline = options.now().getTime() + options.waitMs;
  await mkdir(dirname(path), { recursive: true });
  // Identifies this holder, so it only ever releases a lock that is still its own.
  const token = randomBytes(16).toString("hex");

  for (;;) {
    try {
      const handle = await open(path, "wx");
      try {
        await handle.write(
          JSON.stringify({ pid: process.pid, at: options.now().toISOString(), token }),
        );
      } finally {
        await handle.close();
      }
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const held = await stat(path).catch(() => undefined);
      if (held !== undefined && options.now().getTime() - held.mtimeMs > options.staleAfterMs) {
        await rm(path, { force: true });
        continue;
      }
      if (options.now().getTime() >= deadline)
        return { ok: false, error: { code: "LOCK_TIMEOUT", path } };
      await sleep(pollMs);
    }
  }

  try {
    return {
      ok: true,
      value: await work({ stillHeld: async () => (await tokenIn(path)) === token }),
    };
  } finally {
    // Someone who took over a stale lock owns it now; deleting theirs would let a third in.
    if ((await tokenIn(path)) === token) await rm(path, { force: true });
  }
}

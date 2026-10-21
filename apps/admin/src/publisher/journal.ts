import { mkdir, open, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { MAXIMUM_STATUS_LIST_BYTES } from "@custos/core";

/**
 * The publisher's append-only record of every revocation it has made: the
 * record of truth (ADR 0014, step 3). A signed list can show it was not edited,
 * but not that it is not an older copy, so a list rebuilt from state alone
 * could quietly lose a revocation. The journal is appended and fsynced before
 * any list is signed, and every publish is built from it.
 *
 * It is also the interim evidence of who revoked what and why: the audit
 * service cannot be told when this machine publishes with A switched off.
 */
export interface JournalEntry {
  readonly index: number;
  /** ISO 8601, the operator machine's clock. */
  readonly at: string;
  readonly operator: string;
  readonly reason: string;
  readonly agentDid?: string;
}

export type JournalError =
  | { readonly code: "JOURNAL_CORRUPT"; readonly line: number; readonly reason: string }
  | { readonly code: "JOURNAL_UNREADABLE"; readonly reason: string };

export interface JournalContents {
  /** False when the file does not exist yet (nothing has been initialised). */
  readonly exists: boolean;
  readonly entries: readonly JournalEntry[];
  /** A final line cut off by a crash mid-append; the append never completed, so it is ignored. */
  readonly tornTail: boolean;
}

const MAX_FIELD_CHARS = 1024;
const MAX_INDEX = MAXIMUM_STATUS_LIST_BYTES * 8;

/** A status list index: a decimal safe integer that fits in the largest list we will decode. */
export function parseStatusIndex(value: unknown): number | undefined {
  const text = typeof value === "number" ? String(value) : value;
  if (typeof text !== "string" || !/^\d{1,16}$/.test(text)) return undefined;
  const index = Number(text);
  return Number.isSafeInteger(index) && index < MAX_INDEX ? index : undefined;
}

function parseEntry(line: string): JournalEntry | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const index = parseStatusIndex(record.index);
  const { at, operator, reason, agentDid } = record;
  if (index === undefined) return undefined;
  if (typeof at !== "string" || Number.isNaN(new Date(at).getTime())) return undefined;
  if (typeof operator !== "string" || operator === "" || operator.length > MAX_FIELD_CHARS) {
    return undefined;
  }
  if (typeof reason !== "string" || reason === "" || reason.length > MAX_FIELD_CHARS) {
    return undefined;
  }
  if (
    agentDid !== undefined &&
    (typeof agentDid !== "string" || agentDid.length > MAX_FIELD_CHARS)
  ) {
    return undefined;
  }
  return { index, at, operator, reason, ...(agentDid === undefined ? {} : { agentDid }) };
}

/** Creates the journal if it is not there. Idempotent; never truncates. */
export async function ensureJournal(path: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const handle = await open(path, "a");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * Removes a final line cut off by a crash mid-append, so the next entry starts
 * on a clean line instead of being glued onto the broken bytes (which would make
 * the whole journal unreadable and stop the publisher for good). Safe: an
 * append that did not finish was never acknowledged or published.
 */
async function discardTornTail(path: string): Promise<void> {
  let bytes: Buffer;
  try {
    bytes = await readFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (bytes.length === 0 || bytes[bytes.length - 1] === 0x0a) return;
  const handle = await open(path, "r+");
  try {
    await handle.truncate(bytes.lastIndexOf(0x0a) + 1);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * Appends one entry and does not return until it is on disk. The entry is
 * validated first, so a malformed one can never make the journal unreadable.
 */
export async function appendJournal(path: string, entry: JournalEntry): Promise<void> {
  const line = JSON.stringify(entry);
  if (parseEntry(line) === undefined) throw new Error("refusing to journal an invalid entry");
  await mkdir(dirname(path), { recursive: true });
  await discardTornTail(path);
  const handle = await open(path, "a");
  try {
    await handle.write(`${line}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * Reads every entry. A bad line anywhere but a torn final line is an error:
 * quietly skipping it could drop a revocation, so the publisher refuses to
 * publish until a person has looked.
 */
export async function readJournal(
  path: string,
): Promise<{ ok: true; value: JournalContents } | { ok: false; error: JournalError }> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { ok: true, value: { exists: false, entries: [], tornTail: false } };
    }
    return {
      ok: false,
      error: {
        code: "JOURNAL_UNREADABLE",
        reason: error instanceof Error ? error.message : String(error),
      },
    };
  }

  const endsCleanly = text === "" || text.endsWith("\n");
  const lines = text.split("\n");
  if (endsCleanly) lines.pop(); // the empty string after the final newline
  const entries: JournalEntry[] = [];
  let tornTail = false;
  for (const [i, line] of lines.entries()) {
    if (line === "") {
      return { ok: false, error: { code: "JOURNAL_CORRUPT", line: i + 1, reason: "empty line" } };
    }
    const entry = parseEntry(line);
    if (entry !== undefined) {
      entries.push(entry);
      continue;
    }
    if (i === lines.length - 1 && !endsCleanly) {
      tornTail = true;
      continue;
    }
    return {
      ok: false,
      error: { code: "JOURNAL_CORRUPT", line: i + 1, reason: "not a valid entry" },
    };
  }
  return { ok: true, value: { exists: true, entries, tornTail } };
}

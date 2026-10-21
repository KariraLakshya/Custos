import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendJournal, ensureJournal, parseStatusIndex, readJournal } from "./journal.js";

let dir: string;
let path: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "custos-journal-"));
  path = join(dir, "nested", "journal.jsonl");
});
afterEach(() => rm(dir, { recursive: true, force: true }));

const entry = (index: number, extra: Record<string, unknown> = {}) => ({
  index,
  at: "2026-10-21T10:00:00.000Z",
  operator: "lakshya",
  reason: "key leaked",
  ...extra,
});

describe("parseStatusIndex", () => {
  it("accepts a decimal safe integer inside the largest decodable list", () => {
    expect(parseStatusIndex("0")).toBe(0);
    expect(parseStatusIndex("4821")).toBe(4821);
    expect(parseStatusIndex(7)).toBe(7);
    expect(parseStatusIndex(String(16 * 1024 * 1024 * 8 - 1))).toBe(16 * 1024 * 1024 * 8 - 1);
  });

  it("refuses everything else", () => {
    for (const bad of [
      "-1",
      "1.5",
      "0x10",
      " 7",
      "7 ",
      "",
      "1e3",
      "abc",
      "9".repeat(17),
      String(16 * 1024 * 1024 * 8),
      null,
      undefined,
      {},
      [],
      true,
      -3,
      1.5,
      Number.NaN,
    ]) {
      expect(parseStatusIndex(bad as unknown), String(bad)).toBeUndefined();
    }
  });
});

describe("journal", () => {
  it("reports a missing journal as not started", async () => {
    expect(await readJournal(path)).toEqual({
      ok: true,
      value: { exists: false, entries: [], tornTail: false },
    });
  });

  it("creates the journal once, without ever truncating it", async () => {
    await ensureJournal(path);
    await appendJournal(path, entry(5));
    await ensureJournal(path);
    const read = await readJournal(path);
    expect(read).toMatchObject({ ok: true, value: { exists: true } });
    expect(read.ok && read.value.entries).toEqual([entry(5)]);
  });

  it("appends in order and reads every entry back, including the agent DID", async () => {
    await appendJournal(path, entry(5));
    await appendJournal(path, entry(9, { agentDid: "did:web:a.example:agents:x" }));
    const read = await readJournal(path);
    expect(read.ok && read.value.entries).toEqual([
      entry(5),
      entry(9, { agentDid: "did:web:a.example:agents:x" }),
    ]);
    expect((await readFile(path, "utf8")).split("\n")).toHaveLength(3); // two lines and the final newline
  });

  it("refuses to journal an invalid entry, so the file can never become unreadable", async () => {
    const invalid = [
      entry(-1),
      entry(1.5),
      entry(5, { operator: "" }),
      entry(5, { reason: "" }),
      entry(5, { at: "yesterday" }),
      entry(5, { operator: "x".repeat(1025) }),
      entry(5, { agentDid: 7 }),
    ];
    for (const bad of invalid) {
      await expect(appendJournal(path, bad as never)).rejects.toThrow("invalid entry");
    }
    expect(await readJournal(path)).toMatchObject({ ok: true, value: { entries: [] } });
  });

  it("ignores a final line cut off by a crash mid-append, and says so", async () => {
    await appendJournal(path, entry(5));
    await appendFile(path, '{"index":9,"at":"2026-10-21T10:0');
    const read = await readJournal(path);
    expect(read).toMatchObject({ ok: true, value: { tornTail: true } });
    expect(read.ok && read.value.entries).toEqual([entry(5)]);
  });

  it("refuses a damaged line anywhere else: skipping it could drop a revocation", async () => {
    await writeFile(path.replace("nested", ""), "", { flag: "a" }).catch(() => undefined);
    await ensureJournal(path);
    await writeFile(path, `${JSON.stringify(entry(5))}\nnot json\n${JSON.stringify(entry(7))}\n`);
    expect(await readJournal(path)).toEqual({
      ok: false,
      error: { code: "JOURNAL_CORRUPT", line: 2, reason: "not a valid entry" },
    });
  });

  it("refuses an empty line and a complete but invalid last line", async () => {
    await ensureJournal(path);
    await writeFile(path, `${JSON.stringify(entry(5))}\n\n`);
    expect(await readJournal(path)).toMatchObject({
      ok: false,
      error: { code: "JOURNAL_CORRUPT", line: 2 },
    });
    await writeFile(path, `${JSON.stringify(entry(5))}\n{"index":-4}\n`);
    expect(await readJournal(path)).toMatchObject({
      ok: false,
      error: { code: "JOURNAL_CORRUPT", line: 2 },
    });
  });

  it("refuses lines that are JSON but not an entry", async () => {
    await ensureJournal(path);
    for (const line of ["[]", "7", '"x"', "null", '{"index":"5"}']) {
      await writeFile(path, `${line}\n`);
      expect(await readJournal(path), line).toMatchObject({
        ok: false,
        error: { code: "JOURNAL_CORRUPT" },
      });
    }
  });

  it("reports a journal that cannot be read for any reason but being absent", async () => {
    // A directory where the file should be: reading it fails with something other than ENOENT.
    expect(await readJournal(dir)).toMatchObject({
      ok: false,
      error: { code: "JOURNAL_UNREADABLE" },
    });
  });
});

describe("appending after a crash mid-append", () => {
  it("discards the cut-off bytes instead of gluing the next entry onto them", async () => {
    await appendJournal(path, entry(5));
    await appendFile(path, '{"index":9,"at":"2026-10-21T10:0');
    await appendJournal(path, entry(11));
    const read = await readJournal(path);
    expect(read).toMatchObject({ ok: true, value: { tornTail: false } });
    expect(read.ok && read.value.entries).toEqual([entry(5), entry(11)]);
  });

  it("handles a journal that is nothing but a cut-off line", async () => {
    await ensureJournal(path);
    await writeFile(path, '{"index":4,"at":"2026');
    await appendJournal(path, entry(8));
    const read = await readJournal(path);
    expect(read.ok && read.value.entries).toEqual([entry(8)]);
  });

  it("leaves a clean journal exactly as it was", async () => {
    await appendJournal(path, entry(5));
    const before = await readFile(path, "utf8");
    await appendJournal(path, entry(6));
    expect((await readFile(path, "utf8")).startsWith(before)).toBe(true);
  });

  it("copes with a cut-off line that contains multi-byte characters", async () => {
    await appendJournal(path, entry(5));
    await appendFile(path, Buffer.from('{"index":9,"operator":"zo', "utf8"));
    await appendFile(path, Buffer.from([0xc3])); // half of a two-byte character
    await appendJournal(path, entry(7));
    const read = await readJournal(path);
    expect(read.ok && read.value.entries.map((e) => e.index)).toEqual([5, 7]);
  });
});

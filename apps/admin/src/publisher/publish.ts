import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  createStatusList,
  didWebFromDomain,
  issueStatusListCredential,
  publicKeyToMultibase,
  revokedIndexes,
  setRevoked,
  statusListCredentialUrl,
  verifyForeignStatusList,
  type KeyProvider,
  type StatusAnchor,
} from "@custos/core";
import { withLock, writeFileAtomic, type FileOps, type HeldLock } from "./files.js";
import {
  ensureJournal,
  parseStatusIndex,
  readJournal,
  type JournalContents,
  type JournalError,
} from "./journal.js";

export interface PublisherConfig {
  /** The domain the revocation DID is published under (what A's service calls `REVOCATION_DID_DOMAIN`). */
  readonly domain: string;
  /** Holds the journal, the last signed state, and the lock. */
  readonly dir: string;
  /** Where the list is written: a path a static server (or a bucket sync) serves. */
  readonly out: string;
  /** How long a list is promised to be good for: its signed `validUntil - validFrom`. Required. */
  readonly validitySeconds: number;
  /** How often `run` re-signs. Required, and shorter than the validity period. */
  readonly stampSeconds: number;
  /** How far a source list's `validFrom` may be ahead of this clock. */
  readonly maxClockSkewSeconds: number;
  readonly lockStaleMs?: number;
  readonly lockWaitMs?: number;
}

export interface PublisherDeps {
  readonly keyProvider: KeyProvider;
  readonly keyId: string;
  readonly clock: { now(): Date };
  /** The list as a remote host serves it; `undefined` means the host has none (404). Throws when unreachable. */
  readonly fetchHost?: () => Promise<unknown | undefined>;
  /** Revoked indexes from A's database. Optional: one input to the union among several. */
  readonly readDatabaseIndexes?: () => Promise<readonly number[]>;
  readonly fileOps?: FileOps;
  readonly sleep?: (ms: number) => Promise<void>;
}

export type PublishError =
  | JournalError
  | { readonly code: "NO_BASELINE" }
  | { readonly code: "ALREADY_INITIALISED"; readonly where: string }
  | { readonly code: "HOST_UNREACHABLE"; readonly reason: string }
  | { readonly code: "LOCK_TIMEOUT" }
  /** Another process took the lock over mid-publish; nothing was written. */
  | { readonly code: "LOCK_LOST" }
  | { readonly code: "INIT_NEEDS_HOST" }
  /** A list for this very identity exists but is signed by a different key than the one configured. */
  | { readonly code: "KEY_MISMATCH"; readonly where: string }
  | { readonly code: "SIGNING_FAILED"; readonly reason: string }
  | { readonly code: "WRITE_FAILED"; readonly reason: string };

export interface PublishOutcome {
  readonly revokedCount: number;
  readonly validFrom: Date;
  readonly validUntil: Date;
  /** Anything ignored or unreadable that a person should know about. Never contains secrets. */
  readonly warnings: readonly string[];
}

export type PublishResult =
  | { readonly ok: true; readonly value: PublishOutcome }
  | { readonly ok: false; readonly error: PublishError };

export function publisherPaths(config: Pick<PublisherConfig, "dir">) {
  return {
    journal: join(config.dir, "journal.jsonl"),
    state: join(config.dir, "state.json"),
    lock: join(config.dir, "publisher.lock"),
  };
}

export async function publisherIdentity(config: PublisherConfig, deps: PublisherDeps) {
  const publicKey = await deps.keyProvider.getPublicKey(deps.keyId);
  const did = didWebFromDomain(config.domain);
  return {
    did,
    listId: statusListCredentialUrl(config.domain),
    publicKey,
    publicKeyMultibase: publicKeyToMultibase(publicKey),
    verificationMethodId: `${did}#${publicKeyToMultibase(publicKey)}`,
  };
}

/** A file's JSON, `undefined` when absent, or a warning when it is not JSON. */
async function readJsonFile(path: string): Promise<{ value?: unknown; warning?: string }> {
  try {
    return { value: JSON.parse(await readFile(path, "utf8")) as unknown };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    return { warning: `${path} is not readable JSON and was ignored` };
  }
}

interface Sources {
  readonly journal: JournalContents;
  /** Bits from copies that verify under this key. */
  readonly stateBits?: Uint8Array;
  readonly sinkBits?: Uint8Array;
  readonly hostBits?: Uint8Array;
  readonly databaseIndexes: readonly number[];
  readonly hostUnreachable?: string;
  readonly warnings: string[];
}

type GatherError = JournalError | { readonly code: "KEY_MISMATCH"; readonly where: string };

async function gatherSources(
  config: PublisherConfig,
  deps: PublisherDeps,
): Promise<{ ok: true; value: Sources } | { ok: false; error: GatherError }> {
  const paths = publisherPaths(config);
  const warnings: string[] = [];
  const journal = await readJournal(paths.journal);
  if (!journal.ok) return journal;
  if (journal.value.tornTail)
    warnings.push("the journal ended in a cut-off line, which was ignored");

  const identity = await publisherIdentity(config, deps);
  const anchor: StatusAnchor = {
    statusIssuerDid: identity.did,
    statusIssuerPublicKey: identity.publicKey,
    statusListId: identity.listId,
    maxStatusAgeSeconds: config.validitySeconds,
  };
  const now = deps.clock.now();

  // A copy is merged only if it verifies under this publisher's own key. Its
  // age does not matter (a stale list's bits are still true); who signed it does.
  let keyMismatch: string | undefined;
  async function bitsOf(label: string, raw: unknown): Promise<Uint8Array | undefined> {
    if (raw === undefined) return undefined;
    const verified = await verifyForeignStatusList({
      credential: raw,
      anchor,
      now,
      maxClockSkewSeconds: config.maxClockSkewSeconds,
      acceptStale: true,
    });
    if (!verified.ok) {
      // A list for this very identity that this key did not sign means the wrong
      // seed is configured (or someone is interfering). Replacing it would make A
      // and every B reject the new list and fail closed, with the good copy gone.
      const claimed =
        typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {};
      if (
        verified.error.code === "LIST_SIGNATURE_INVALID" &&
        claimed.issuer === identity.did &&
        claimed.id === identity.listId
      ) {
        keyMismatch ??= label;
      }
      warnings.push(`the ${label} copy was ignored: ${verified.error.code}`);
      return undefined;
    }
    return verified.value.list;
  }

  const state = await readJsonFile(paths.state);
  if (state.warning) warnings.push(state.warning);
  const sink = await readJsonFile(config.out);
  if (sink.warning) warnings.push(sink.warning);

  let hostRaw: unknown;
  let hostUnreachable: string | undefined;
  if (deps.fetchHost !== undefined) {
    try {
      hostRaw = await deps.fetchHost();
    } catch (error) {
      hostUnreachable = error instanceof Error ? error.message : String(error);
      warnings.push(`the host could not be read: ${hostUnreachable}`);
    }
  }

  let databaseIndexes: readonly number[] = [];
  if (deps.readDatabaseIndexes !== undefined) {
    try {
      const read = await deps.readDatabaseIndexes();
      const valid = read.filter((index) => parseStatusIndex(index) !== undefined);
      if (valid.length !== read.length)
        warnings.push("some database indexes were out of range and ignored");
      databaseIndexes = valid;
    } catch (error) {
      warnings.push(
        `A's database could not be read, so it was left out: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const stateBits = await bitsOf("state", state.value);
  const sinkBits = await bitsOf("published", sink.value);
  const hostBits = await bitsOf("host", hostRaw);
  if (keyMismatch !== undefined)
    return { ok: false, error: { code: "KEY_MISMATCH", where: keyMismatch } };
  return {
    ok: true,
    value: {
      journal: journal.value,
      ...(stateBits === undefined ? {} : { stateBits }),
      ...(sinkBits === undefined ? {} : { sinkBits }),
      ...(hostBits === undefined ? {} : { hostBits }),
      databaseIndexes,
      ...(hostUnreachable === undefined ? {} : { hostUnreachable }),
      warnings,
    },
  };
}

const hasServedList = (sources: Sources): boolean =>
  sources.stateBits !== undefined ||
  sources.sinkBits !== undefined ||
  sources.hostBits !== undefined;

/**
 * True when publishing cannot start from nothing by mistake: a journal exists,
 * or a list signed by this key survives somewhere. Without one of those a lost
 * journal and state would publish an empty list over every earlier revocation.
 */
export async function hasBaseline(
  config: PublisherConfig,
  deps: PublisherDeps,
): Promise<{ ok: true; value: boolean } | { ok: false; error: PublishError }> {
  const sources = await gatherSources(config, deps);
  if (!sources.ok) return sources;
  return { ok: true, value: sources.value.journal.exists || hasServedList(sources.value) };
}

async function buildAndWrite(
  config: PublisherConfig,
  deps: PublisherDeps,
  sources: Sources,
  lock: HeldLock,
): Promise<PublishResult> {
  const identity = await publisherIdentity(config, deps);
  const indexes = new Set<number>(sources.journal.entries.map((entry) => entry.index));
  for (const bits of [sources.stateBits, sources.sinkBits, sources.hostBits]) {
    if (bits !== undefined) for (const index of revokedIndexes(bits)) indexes.add(index);
  }
  for (const index of sources.databaseIndexes) indexes.add(index);

  let highest = 0;
  for (const index of indexes) highest = Math.max(highest, index);
  let list = createStatusList(highest + 1);
  for (const index of indexes) {
    const updated = setRevoked(list, index, true);
    // Unreachable: the list is sized to the highest index above. A hard failure,
    // not a skip: dropping a bit would publish a revoked agent as active.
    if (!updated.ok) throw new Error(`status list index ${index} out of range`);
    list = updated.value;
  }

  const now = deps.clock.now();
  const validUntil = new Date(now.getTime() + config.validitySeconds * 1000);
  const issued = await issueStatusListCredential({
    list,
    issuerDid: identity.did,
    signer: {
      id: identity.verificationMethodId,
      sign: (input) => deps.keyProvider.sign(deps.keyId, input.data),
    },
    statusListCredentialUrl: identity.listId,
    now,
    validUntil,
  });
  if (!issued.ok)
    return { ok: false, error: { code: "SIGNING_FAILED", reason: issued.error.reason } };

  const text = `${JSON.stringify(issued.value)}\n`;
  const writeOptions = {
    ...(deps.fileOps === undefined ? {} : { ops: deps.fileOps }),
    ...(deps.sleep === undefined ? {} : { sleep: deps.sleep }),
  };
  const warnings = [...sources.warnings];
  // If another process took the lock over while this was working, its view of
  // the journal is newer than ours: writing now could overwrite its revocation.
  if (!(await lock.stillHeld())) return { ok: false, error: { code: "LOCK_LOST" } };
  try {
    await writeFileAtomic(config.out, text, writeOptions);
  } catch (error) {
    return {
      ok: false,
      error: {
        code: "WRITE_FAILED",
        reason: error instanceof Error ? error.message : String(error),
      },
    };
  }
  // The state is a cache; failing to refresh it does not undo a publish.
  try {
    await writeFileAtomic(publisherPaths(config).state, text, writeOptions);
  } catch (error) {
    warnings.push(
      `the state file was not refreshed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return { ok: true, value: { revokedCount: indexes.size, validFrom: now, validUntil, warnings } };
}

/**
 * One publish: under the lock, read every source, take the union, sign it with
 * a fresh `validFrom`/`validUntil`, and write it. Used for a stamp (nothing new)
 * and after a revocation (the journal has one more line). `init` is the one
 * time a publish may start from nothing.
 */
export async function publishOnce(
  config: PublisherConfig,
  deps: PublisherDeps,
  options: {
    readonly init?: boolean;
    /**
     * For `init` without a host to ask: the operator states that this publisher
     * has never published, so nothing exists for an empty list to replace.
     */
    readonly acknowledgeNoPublishedList?: boolean;
  } = {},
): Promise<PublishResult> {
  const paths = publisherPaths(config);
  const locked = await withLock(
    paths.lock,
    {
      now: () => deps.clock.now(),
      ...(deps.sleep === undefined ? {} : { sleep: deps.sleep }),
      staleAfterMs: config.lockStaleMs ?? 120_000,
      waitMs: config.lockWaitMs ?? 30_000,
    },
    async (lock): Promise<PublishResult> => {
      const gathered = await gatherSources(config, deps);
      if (!gathered.ok) return gathered;
      const sources = gathered.value;

      if (options.init === true) {
        if (sources.journal.exists) {
          return { ok: false, error: { code: "ALREADY_INITIALISED", where: paths.journal } };
        }
        if (hasServedList(sources)) {
          return {
            ok: false,
            error: {
              code: "ALREADY_INITIALISED",
              where: "a list signed by this key is already served",
            },
          };
        }
        // An empty list published over a real one would un-revoke everything: start
        // from nothing only when a host was asked and has none, or the operator says
        // nothing was ever published.
        if (deps.fetchHost === undefined && options.acknowledgeNoPublishedList !== true) {
          return { ok: false, error: { code: "INIT_NEEDS_HOST" } };
        }
        // A host that cannot be read might be serving a list: start from nothing only when sure.
        if (sources.hostUnreachable !== undefined) {
          return {
            ok: false,
            error: { code: "HOST_UNREACHABLE", reason: sources.hostUnreachable },
          };
        }
        await ensureJournal(paths.journal);
      } else if (!sources.journal.exists && !hasServedList(sources)) {
        return { ok: false, error: { code: "NO_BASELINE" } };
      }
      return buildAndWrite(config, deps, sources, lock);
    },
  );
  return locked.ok ? locked.value : { ok: false, error: { code: "LOCK_TIMEOUT" } };
}

const FATAL: ReadonlySet<PublishError["code"]> = new Set([
  "NO_BASELINE",
  "ALREADY_INITIALISED",
  "JOURNAL_CORRUPT",
  "JOURNAL_UNREADABLE",
]);

/**
 * Re-signs every `stampSeconds` until `signal` aborts. A transient failure
 * (host down, lock busy, write refused) is reported and the next stamp tries
 * again; one that needs a person (no baseline, a corrupt journal) stops the loop.
 */
export async function runPublisher(
  config: PublisherConfig,
  deps: PublisherDeps,
  options: {
    readonly signal: AbortSignal;
    readonly onCycle: (result: PublishResult) => void;
  },
): Promise<PublishResult | undefined> {
  // A stop that arrives while a cycle is running has already fired its event, so
  // the wait checks the signal first instead of waiting for an event that is gone.
  const sleep =
    deps.sleep ??
    ((ms: number) =>
      new Promise<void>((resolve) => {
        if (options.signal.aborted) return resolve();
        const timer = setTimeout(resolve, ms);
        options.signal.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            resolve();
          },
          { once: true },
        );
      }));
  let last: PublishResult | undefined;
  while (!options.signal.aborted) {
    last = await publishOnce(config, deps);
    options.onCycle(last);
    if (!last.ok && FATAL.has(last.error.code)) return last;
    await sleep(config.stampSeconds * 1000);
  }
  return last;
}

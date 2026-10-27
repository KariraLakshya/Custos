import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { pullAuditLedger, type PullAuditLedgerError, type SealStore } from "@custos/audit-client";
import { multibaseToPublicKey, type AuditRecord } from "@custos/core";

/**
 * Where `audit-log` remembers, per audit log, the newest seal it verified and
 * every key it has trusted (ADR 0017 §5 and key rotation).
 */
export function defaultSealFile(): string {
  return join(homedir(), ".custos", "audit-seal.json");
}

/** By audit log DID. `keys` are the pinned seal keys, multibase, oldest first. */
type Remembered = Record<
  string,
  { readonly seq: number; readonly seal: string | null; readonly keys: readonly string[] }
>;

function isRememberedEntry(entry: unknown): boolean {
  if (typeof entry !== "object" || entry === null) return false;
  const { seq, seal, keys } = entry as { seq?: unknown; seal?: unknown; keys?: unknown };
  return (
    typeof seq === "number" &&
    (seal === null || typeof seal === "string") &&
    Array.isArray(keys) &&
    keys.length > 0 &&
    keys.every((key) => typeof key === "string")
  );
}

async function readRemembered(path: string): Promise<Remembered> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw new Error(`cannot read the remembered audit seals in ${path}; fix or remove it`);
  }
  if (typeof parsed === "object" && parsed !== null) {
    const entries = Object.values(parsed);
    if (entries.every(isRememberedEntry)) return parsed as Remembered;
    if (
      entries.some((entry) => typeof entry === "object" && entry !== null && !("keys" in entry))
    ) {
      throw new Error(
        `${path} was written by an earlier custos that did not pin seal keys; remove it and run audit-log again`,
      );
    }
  }
  // Refusing beats starting over: an empty file would forget what it must check.
  throw new Error(`cannot read the remembered audit seals in ${path}; fix or remove it`);
}

export type AuditLogError =
  | PullAuditLedgerError
  /**
   * The audit service publishes a key this machine has not trusted for this
   * log. Compare `current` with the key the service's operator gave you, then
   * pass it to `--accept-key`. Seals under the `previous` keys stay checked.
   */
  | {
      readonly code: "KEY_CHANGED";
      readonly previous: readonly string[];
      readonly current: string;
    };

export type AuditLogResult =
  | {
      readonly verified: true;
      readonly log: string;
      readonly headSeq: number;
      readonly sealedThrough: number;
      /** Entries recorded after the newest seal: not sealed yet. */
      readonly unsealedCount: number;
      readonly records: readonly { readonly seq: number; readonly record: AuditRecord }[];
      /**
       * Whether seals copied outside the audit database were checked (ADR 0017
       * part 2a). False means the newest entries were only checked against
       * seals the audit service itself served and this machine remembered.
       */
      readonly outsideSealsChecked: boolean;
      /** The newest outside copy checked, and when it was sealed. */
      readonly newestOutsideSeal?: { readonly seq: number; readonly sealedAt: string };
      /** The seal keys trusted for this log after this check. */
      readonly trustedKeys: readonly string[];
    }
  | { readonly verified: false; readonly error: AuditLogError };

/**
 * Pulls the audit ledger for `agentDid` (or everyone) and verifies it
 * independently: the chain, the served seal, and the seal this machine
 * remembered for this log from its last check, so a log shortened or
 * rewritten since then is reported (`TRUNCATED`, `DIVERGED`). On success the
 * newest seal is remembered for next time. A failure is reported, never
 * dropped.
 *
 * With `sealStore`, it also checks every seal copied outside the audit
 * database from the remembered one on (all of them on a first run), not just
 * the newest: the service's own identity could sign a higher seal over a
 * rewritten log and copy it, but the older copies still contradict it.
 *
 * Keys (ADR 0017, key rotation): the first check of a log trusts the key the
 * service publishes and pins it. Afterwards a different published key is
 * `KEY_CHANGED` until a person passes it in `acceptKeys`; pinned keys are
 * never dropped, so seals made before a rotation stay checked under their
 * own key. A seal by a key never trusted is `UNTRUSTED_KEY`, naming the key.
 */
export async function pullAuditLog(params: {
  readonly auditUrl: string;
  readonly agentDid?: string;
  readonly sealFile?: string;
  readonly sealStore?: Pick<SealStore, "list">;
  /** Keys a person has checked and accepts for this log, multibase. */
  readonly acceptKeys?: readonly string[];
}): Promise<AuditLogResult> {
  const accepted = params.acceptKeys ?? [];
  for (const key of accepted) {
    if (!multibaseToPublicKey(key).ok) throw new Error(`not an Ed25519 multibase key: ${key}`);
  }
  const sealFile = params.sealFile ?? defaultSealFile();
  const remembered = await readRemembered(sealFile);
  let outside: readonly string[] = [];
  let trusted: readonly string[] = [];
  let keyChanged: { previous: readonly string[]; current: string } | undefined;

  const pulled = await pullAuditLedger({
    auditUrl: params.auditUrl,
    ...(params.agentDid === undefined ? {} : { agentDid: params.agentDid }),
    heldSeals: (log) => {
      const seal = remembered[log]?.seal;
      return seal === null || seal === undefined ? [] : [seal];
    },
    trustedKeys: (log, published) => {
      const pinned = remembered[log]?.keys;
      // First check of this log: trust what it publishes now, and pin it.
      const base = pinned ?? [published];
      trusted = [...new Set([...base, ...accepted])];
      if (!trusted.includes(published)) keyChanged = { previous: base, current: published };
      return trusted;
    },
    ...(params.sealStore === undefined
      ? {}
      : {
          outsideSeals: async (log: string) => {
            outside = await params.sealStore!.list(log, Math.max(1, remembered[log]?.seq ?? 1));
            return outside;
          },
        }),
  });

  if (keyChanged !== undefined) {
    const current = keyChanged.current;
    const onlyTheNewKey =
      pulled.ok ||
      (pulled.error.code === "SEAL_INVALID" &&
        pulled.error.error.code === "UNTRUSTED_KEY" &&
        pulled.error.error.key === current);
    // A real failure under the trusted keys outranks the key change.
    if (onlyTheNewKey) {
      return { verified: false, error: { code: "KEY_CHANGED", ...keyChanged } };
    }
  }
  if (!pulled.ok) return { verified: false, error: pulled.error };
  const ledger = pulled.value;
  const newest = ledger.newestSeal;
  const known = remembered[ledger.log];

  // Every seal here verified; keep the newest one, never stepping back.
  const newestEnvelope = [
    ...(ledger.servedSeal === null ? [] : [ledger.servedSeal]),
    ...outside,
  ].find((seal) => sealClaims(seal).seq === newest?.seq);
  const advances =
    newest !== undefined && newestEnvelope !== undefined && (known?.seq ?? 0) < newest.seq;
  const keysGrew = known === undefined || trusted.some((key) => !known.keys.includes(key));
  if (advances || keysGrew) {
    const next: Remembered = {
      ...remembered,
      [ledger.log]: {
        seq: advances ? newest!.seq : (known?.seq ?? 0),
        seal: advances ? newestEnvelope! : (known?.seal ?? null),
        keys: trusted,
      },
    };
    await mkdir(dirname(sealFile), { recursive: true });
    const temporary = `${sealFile}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(next, null, 2)}\n`);
    await rename(temporary, sealFile);
  }

  return {
    verified: true,
    log: ledger.log,
    headSeq: ledger.headSeq,
    sealedThrough: newest?.seq ?? 0,
    unsealedCount: ledger.unsealedCount,
    records:
      params.agentDid === undefined
        ? ledger.records
        : ledger.records.filter((entry) => entry.record.agentDid === params.agentDid),
    outsideSealsChecked: params.sealStore !== undefined,
    ...(outside.length === 0
      ? {}
      : { newestOutsideSeal: sealClaims(outside[outside.length - 1]!) }),
    trustedKeys: trusted,
  };
}

/** `seq` and `sealedAt` from a seal that has already verified. */
function sealClaims(seal: string): { seq: number; sealedAt: string } {
  return JSON.parse(Buffer.from(seal.split(".")[0] ?? "", "base64url").toString("utf8")) as {
    seq: number;
    sealedAt: string;
  };
}

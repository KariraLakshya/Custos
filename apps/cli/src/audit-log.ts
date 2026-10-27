import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { pullAuditLedger, type PullAuditLedgerError, type SealStore } from "@custos/audit-client";
import type { AuditRecord } from "@custos/core";

/** Where `audit-log` remembers the newest seal it verified, per audit log (ADR 0017 §5). */
export function defaultSealFile(): string {
  return join(homedir(), ".custos", "audit-seal.json");
}

/** By audit log DID: the newest seal verified for that log. */
type RememberedSeals = Record<string, { readonly seq: number; readonly seal: string }>;

async function readRemembered(path: string): Promise<RememberedSeals> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      Object.values(parsed).every(
        (entry: unknown) =>
          typeof entry === "object" &&
          entry !== null &&
          typeof (entry as { seq?: unknown }).seq === "number" &&
          typeof (entry as { seal?: unknown }).seal === "string",
      )
    ) {
      return parsed as RememberedSeals;
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
  }
  // Refusing beats starting over: an empty file would forget what it must check.
  throw new Error(`cannot read the remembered audit seals in ${path}; fix or remove it`);
}

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
    }
  | { readonly verified: false; readonly error: PullAuditLedgerError };

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
 */
export async function pullAuditLog(params: {
  readonly auditUrl: string;
  readonly agentDid?: string;
  readonly sealFile?: string;
  readonly sealStore?: Pick<SealStore, "list">;
}): Promise<AuditLogResult> {
  const sealFile = params.sealFile ?? defaultSealFile();
  const remembered = await readRemembered(sealFile);
  let outside: readonly string[] = [];

  const pulled = await pullAuditLedger({
    auditUrl: params.auditUrl,
    ...(params.agentDid === undefined ? {} : { agentDid: params.agentDid }),
    heldSeals: (log) => (remembered[log] === undefined ? [] : [remembered[log].seal]),
    ...(params.sealStore === undefined
      ? {}
      : {
          outsideSeals: async (log: string) => {
            outside = await params.sealStore!.list(log, remembered[log]?.seq ?? 1);
            return outside;
          },
        }),
  });
  if (!pulled.ok) return { verified: false, error: pulled.error };
  const ledger = pulled.value;
  const newest = ledger.newestSeal;

  // Every seal here verified; keep the newest one, never stepping back.
  const newestEnvelope = [
    ...(ledger.servedSeal === null ? [] : [ledger.servedSeal]),
    ...outside,
  ].find((seal) => sealClaims(seal).seq === newest?.seq);
  if (
    newest !== undefined &&
    newestEnvelope !== undefined &&
    (remembered[ledger.log]?.seq ?? 0) < newest.seq
  ) {
    const next = { ...remembered, [ledger.log]: { seq: newest.seq, seal: newestEnvelope } };
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
  };
}

/** `seq` and `sealedAt` from a seal that has already verified. */
function sealClaims(seal: string): { seq: number; sealedAt: string } {
  return JSON.parse(Buffer.from(seal.split(".")[0] ?? "", "base64url").toString("utf8")) as {
    seq: number;
    sealedAt: string;
  };
}

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { pullAuditLedger, type PullAuditLedgerError } from "@custos/audit-client";
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
    }
  | { readonly verified: false; readonly error: PullAuditLedgerError };

/**
 * Pulls the audit ledger for `agentDid` (or everyone) and verifies it
 * independently: the chain, the served seal, and the seal this machine
 * remembered for this log from its last check, so a log shortened or
 * rewritten since then is reported (`TRUNCATED`, `DIVERGED`). On success the
 * newest seal is remembered for next time. A failure is reported, never
 * dropped.
 */
export async function pullAuditLog(params: {
  readonly auditUrl: string;
  readonly agentDid?: string;
  readonly sealFile?: string;
}): Promise<AuditLogResult> {
  const sealFile = params.sealFile ?? defaultSealFile();
  const remembered = await readRemembered(sealFile);

  const pulled = await pullAuditLedger({
    auditUrl: params.auditUrl,
    ...(params.agentDid === undefined ? {} : { agentDid: params.agentDid }),
    heldSeals: (log) => (remembered[log] === undefined ? [] : [remembered[log].seal]),
  });
  if (!pulled.ok) return { verified: false, error: pulled.error };
  const ledger = pulled.value;
  const newest = ledger.newestSeal;

  // The served seal verified; keep it when it is the newest, never stepping back.
  if (
    newest !== undefined &&
    ledger.servedSeal !== null &&
    newest.seq === sealSeq(ledger.servedSeal) &&
    (remembered[ledger.log]?.seq ?? 0) < newest.seq
  ) {
    const next = { ...remembered, [ledger.log]: { seq: newest.seq, seal: ledger.servedSeal } };
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
  };
}

/** `seq` from a seal that has already verified. */
function sealSeq(seal: string): number | undefined {
  const claims = JSON.parse(
    Buffer.from(seal.split(".")[0] ?? "", "base64url").toString("utf8"),
  ) as {
    seq?: unknown;
  };
  return typeof claims.seq === "number" ? claims.seq : undefined;
}

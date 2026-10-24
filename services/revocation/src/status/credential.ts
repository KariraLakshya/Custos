import { isNotNull } from "drizzle-orm";
import {
  createStatusList,
  issueStatusListCredential,
  setRevoked,
  type CredentialSigner,
  type SignedCredential,
} from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { externalRevokedIndexes, statusListEntries } from "../db/schema.js";
import type { RevocationDb } from "../db/client.js";

export type StatusListCredentialError = {
  readonly code: "SIGNING_FAILED";
  readonly reason: string;
};

/**
 * Rebuilds the bitstring from the revocation rows on every request rather
 * than caching it. At Phase 3 scale this is a single indexed scan, and a
 * derived-on-read list cannot drift out of sync with the rows that are the
 * actual source of truth. If it ever shows up in a profile, cache it behind
 * a version counter — do not make the rows follow the bitstring.
 */
async function buildBitstring(db: RevocationDb): Promise<Uint8Array> {
  const rows = await db
    .select({ statusListIndex: statusListEntries.statusListIndex })
    .from(statusListEntries)
    .where(isNotNull(statusListEntries.revokedAt));
  // Revoked slots that came from the published list and have no row above.
  const external = await db
    .select({ statusListIndex: externalRevokedIndexes.statusListIndex })
    .from(externalRevokedIndexes);

  const indexes = [...rows, ...external].map((row) => row.statusListIndex);
  const highestIndex = indexes.reduce((max, index) => Math.max(max, index), 0);
  let list = createStatusList(highestIndex + 1);
  for (const index of indexes) {
    const updated = setRevoked(list, index, true);
    // Unreachable: the list is sized to the highest index above. Kept as a
    // hard failure rather than a silent skip — quietly dropping a bit would
    // publish a revoked agent as active.
    if (!updated.ok) {
      throw new Error(`status list index ${index} out of range`);
    }
    list = updated.value;
  }
  return list;
}

/**
 * The publicly fetchable, signed proof of who has been revoked — the durable
 * half of Phase 3 (the tombstone push is the fast half; see
 * docs/adr/0005-revocation-architecture.md). A verifier downloads the whole
 * list and reads one bit, so this service never learns which agent it was
 * asked about.
 */
export async function buildStatusListCredential(params: {
  readonly db: RevocationDb;
  readonly issuerDid: string;
  readonly signer: CredentialSigner;
  readonly statusListCredentialUrl: string;
  readonly now: Date;
  readonly ttlMs?: number;
  readonly validUntil?: Date;
  readonly memo?: StatusListMemo;
}): Promise<Result<SignedCredential, StatusListCredentialError>> {
  const { db, ...rest } = params;
  return signStatusList({ ...rest, list: await buildBitstring(db) });
}

/** Signs `list`, reusing `memo`'s last signature when it applies (ADR 0016). */
export async function signStatusList(params: {
  readonly list: Uint8Array;
  readonly issuerDid: string;
  readonly signer: CredentialSigner;
  readonly statusListCredentialUrl: string;
  readonly now: Date;
  readonly ttlMs?: number;
  readonly validUntil?: Date;
  readonly memo?: StatusListMemo;
}): Promise<Result<SignedCredential, StatusListCredentialError>> {
  const { list, issuerDid, signer, statusListCredentialUrl, now, ttlMs, validUntil, memo } = params;
  const sign = async (): Promise<Result<SignedCredential, StatusListCredentialError>> => {
    const issued = await issueStatusListCredential({
      list,
      issuerDid,
      signer,
      statusListCredentialUrl,
      now,
      ...(ttlMs === undefined ? {} : { ttlMs }),
      ...(validUntil === undefined ? {} : { validUntil }),
    });
    if (!issued.ok) {
      return err({ code: "SIGNING_FAILED", reason: issued.error.reason });
    }
    return ok(issued.value);
  };
  if (memo === undefined) return sign();

  const contents = Buffer.from(list).toString("hex");
  const age = now.getTime() - (memo.entry?.signedAt ?? 0);
  if (memo.entry?.contents === contents && age >= 0 && age < memo.reuseMs) {
    return memo.entry.result;
  }
  // Set before awaiting, so requests arriving while this one signs share it.
  const entry = { contents, signedAt: now.getTime(), result: sign() };
  memo.entry = entry;
  const result = await entry.result;
  // A failed signature is not reused: the next request tries again.
  if (!result.ok && memo.entry === entry) memo.entry = undefined;
  return result;
}

/**
 * The last signed status list, reused for requests within `reuseMs` while the
 * list's contents are unchanged (ADR 0016). The route is open to anyone, and
 * with the key in KMS every signature is a billed, rate-limited network call
 * on the key that also signs tombstones; without this, a loop of anonymous
 * requests could use up that allowance and block revocations. A new
 * revocation changes the contents and is signed at once, so reuse never
 * delays a cut-off; it only lets `validFrom` lag by up to `reuseMs`, which
 * must stay well below the subscribers' staleness bound.
 */
export interface StatusListMemo {
  readonly reuseMs: number;
  entry:
    | {
        readonly contents: string;
        readonly signedAt: number;
        readonly result: Promise<Result<SignedCredential, StatusListCredentialError>>;
      }
    | undefined;
}

export function createStatusListMemo(reuseMs: number): StatusListMemo {
  return { reuseMs, entry: undefined };
}

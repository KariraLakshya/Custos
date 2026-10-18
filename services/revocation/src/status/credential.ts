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
}): Promise<Result<SignedCredential, StatusListCredentialError>> {
  const { db, issuerDid, signer, statusListCredentialUrl, now, ttlMs, validUntil } = params;
  const issued = await issueStatusListCredential({
    list: await buildBitstring(db),
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
}

import { isNotNull } from "drizzle-orm";
import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  buildStatusListSubject,
  createStatusList,
  issueCredential,
  setRevoked,
  type CredentialSigner,
  type SignedCredential,
} from "@custos/core";
import { err, ok, type Result } from "@custos/contracts";
import { statusListEntries } from "../db/schema.js";
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

  const highestIndex = rows.reduce((max, row) => Math.max(max, row.statusListIndex), 0);
  let list = createStatusList(highestIndex + 1);
  for (const row of rows) {
    const updated = setRevoked(list, row.statusListIndex, true);
    // Unreachable: the list is sized to the highest index above. Kept as a
    // hard failure rather than a silent skip — quietly dropping a bit would
    // publish a revoked agent as active.
    if (!updated.ok) {
      throw new Error(`status list index ${row.statusListIndex} out of range`);
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
}): Promise<Result<SignedCredential, StatusListCredentialError>> {
  const { db, issuerDid, signer, statusListCredentialUrl, now, ttlMs } = params;

  const list = await buildBitstring(db);
  const issued = await issueCredential({
    unsignedCredential: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: statusListCredentialUrl,
      type: ["VerifiableCredential", BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
      issuer: issuerDid,
      validFrom: now.toISOString(),
      credentialSubject: {
        ...buildStatusListSubject({
          id: `${statusListCredentialUrl}#list`,
          list,
          ...(ttlMs === undefined ? {} : { ttlMs }),
        }),
      },
    },
    signer,
  });
  if (!issued.ok) {
    return err({ code: "SIGNING_FAILED", reason: issued.error.reason });
  }
  return ok(issued.value);
}

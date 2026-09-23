import { verifyAuditRecord, type AuditRecord, type DidWebDocument } from "@custos/core";

export interface AuditLogEntry {
  readonly verified: boolean;
  readonly record?: AuditRecord;
  readonly reason?: string;
}

/** Same hand-rolled base58 decode used by services/vault's revocation cache and services/revocation's own tests — no new dependency for one primitive. */
function decodeBase58(input: string): Uint8Array {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const bytes: number[] = [];
  for (const char of input) {
    let carry = ALPHABET.indexOf(char);
    if (carry < 0) throw new Error(`invalid base58 character: ${char}`);
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i]! * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of input) {
    if (char !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

/** Public key of the audit service's own signing identity, from its DID document. */
function publicKeyFrom(didDocument: DidWebDocument): Uint8Array {
  const multibase = didDocument.verificationMethod[0].publicKeyMultibase;
  // Strip the multibase "z" prefix and the 2-byte multicodec ed25519-pub header.
  return decodeBase58(multibase.slice(1)).slice(2);
}

/**
 * Pulls every audit record for `agentDid` (or every record, if omitted) and
 * independently verifies each one against the audit service's own resolved
 * DID document — the same "don't trust, verify" pattern as `custos verify`.
 * A record that fails to verify is reported, not silently dropped.
 */
export async function pullAuditLog(params: {
  readonly auditUrl: string;
  readonly agentDid?: string;
}): Promise<readonly AuditLogEntry[]> {
  const { auditUrl, agentDid } = params;

  const didResponse = await fetch(new URL("/.well-known/did.json", auditUrl));
  if (!didResponse.ok) {
    throw new Error(`could not resolve audit service's DID document: HTTP ${didResponse.status}`);
  }
  const publicKey = publicKeyFrom((await didResponse.json()) as DidWebDocument);

  const recordsUrl = new URL("/records", auditUrl);
  if (agentDid !== undefined) recordsUrl.searchParams.set("agentId", agentDid);
  const recordsResponse = await fetch(recordsUrl);
  if (!recordsResponse.ok) {
    throw new Error(`could not pull audit records: HTTP ${recordsResponse.status}`);
  }
  const { records } = (await recordsResponse.json()) as { records: readonly string[] };

  return records.map((record) => {
    const verified = verifyAuditRecord({ record, publicKey });
    if (verified.ok) return { verified: true, record: verified.value };
    return { verified: false, reason: verified.error.code };
  });
}

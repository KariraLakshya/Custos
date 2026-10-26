import { sha256 } from "@noble/hashes/sha2.js";
import { verify } from "../crypto/ed25519.js";
import { err, ok, type Result } from "../result.js";
import { isAuditRecord, type AuditRecord } from "./record.js";

/**
 * The audit log as a hash chain with signed seals (ADR 0017). Every entry is
 * linked to the one before it by a hash; the head of the chain is signed now
 * and then (a "seal"). Pure: hashing and verification only, no I/O.
 */

const ENTRY_DOMAIN = new TextEncoder().encode("custos.audit.entry.v1\u0000");

/** `prevHash` of entry 1: 32 zero bytes. */
export const AUDIT_GENESIS_HASH = "0".repeat(64);

export const AUDIT_SEAL_TYPE = "custos-audit-seal+v1";

/**
 * An entry as served. `payload` is the record exactly as it was stored at
 * append; it is absent when the entry belongs to another agent than the one
 * asked about, so the chain can still be checked without its contents.
 */
export interface ServedAuditEntry {
  readonly seq: number;
  readonly payloadHash: string;
  readonly payload?: string;
}

/** The signed claims of a seal: the chain's head at `seq` (ADR 0017 §2). */
export interface AuditSeal {
  readonly typ: typeof AUDIT_SEAL_TYPE;
  /** The audit service's DID: a seal belongs to exactly one log. */
  readonly log: string;
  readonly seq: number;
  readonly headHash: string;
  readonly sealedAt: string;
}

/** KMS-shaped signing callback, the same shape as `AuditRecordSigner`. */
export interface AuditSealSigner {
  readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
}

export type IssueAuditSealError = { readonly code: "SIGNING_FAILED"; readonly reason: string };

export type VerifyAuditSealError =
  | { readonly code: "MALFORMED_SEAL"; readonly reason: string }
  | { readonly code: "WRONG_LOG" }
  | { readonly code: "SIGNATURE_INVALID" };

export type VerifyAuditLedgerError =
  | { readonly code: "MALFORMED_ENTRY"; readonly index: number; readonly reason: string }
  /** Entries must run 1, 2, 3, ... with nothing missing: a gap is a deleted entry. */
  | { readonly code: "SEQUENCE_GAP"; readonly expected: number; readonly found: number }
  /** The payload served does not match the hash the chain was built on: an edited entry. */
  | { readonly code: "PAYLOAD_MISMATCH"; readonly seq: number }
  | { readonly code: "MALFORMED_RECORD"; readonly seq: number }
  | { readonly code: "SEAL_INVALID"; readonly error: VerifyAuditSealError }
  /** A seal covers entries the log no longer has: newest entries were deleted. */
  | { readonly code: "TRUNCATED"; readonly sealSeq: number; readonly headSeq: number }
  /** The log at a seal's position is not what was sealed: history was rewritten. */
  | { readonly code: "DIVERGED"; readonly seq: number };

export interface VerifiedAuditLedger {
  /** Every entry whose contents were served, in order, with its record. */
  readonly records: readonly { readonly seq: number; readonly record: AuditRecord }[];
  /** The last entry served; 0 for an empty log. */
  readonly headSeq: number;
  /** The newest seal that verified and matched the log; undefined when none was given. */
  readonly newestSeal?: AuditSeal;
  /** Entries after the newest seal: recorded, but not sealed yet. */
  readonly unsealedCount: number;
}

const HEX_32_BYTES = /^[0-9a-f]{64}$/;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function isSeq(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

/** The record as stored and hashed: serialised once, at append, and never rebuilt. */
export function serializeAuditRecord(record: AuditRecord): string {
  return JSON.stringify(record);
}

export function computeAuditPayloadHash(payload: string): string {
  return hex(sha256(new TextEncoder().encode(payload)));
}

/**
 * `SHA-256("custos.audit.entry.v1" ‖ 0x00 ‖ seq (8 bytes, big-endian) ‖
 * prevHash ‖ payloadHash)`. Hashing the payload's hash rather than the payload
 * lets another agent's entry be served as its hash alone.
 */
export function computeAuditEntryHash(params: {
  readonly seq: number;
  readonly prevHash: string;
  readonly payloadHash: string;
}): string {
  const { seq, prevHash, payloadHash } = params;
  if (!isSeq(seq)) throw new Error("seq must be a positive safe integer");
  if (!HEX_32_BYTES.test(prevHash) || !HEX_32_BYTES.test(payloadHash)) {
    throw new Error("hashes must be 64 lowercase hex characters");
  }
  const seqBytes = new Uint8Array(8);
  new DataView(seqBytes.buffer).setBigUint64(0, BigInt(seq));
  const input = new Uint8Array(ENTRY_DOMAIN.length + 8 + 64);
  input.set(ENTRY_DOMAIN, 0);
  input.set(seqBytes, ENTRY_DOMAIN.length);
  input.set(Buffer.from(prevHash, "hex"), ENTRY_DOMAIN.length + 8);
  input.set(Buffer.from(payloadHash, "hex"), ENTRY_DOMAIN.length + 40);
  return hex(sha256(input));
}

/** Signs a seal as a compact envelope, `base64url(JSON).base64url(signature)`. */
export async function issueAuditSeal(params: {
  readonly seal: Omit<AuditSeal, "typ">;
  readonly signer: AuditSealSigner;
}): Promise<Result<string, IssueAuditSealError>> {
  try {
    const claims: AuditSeal = { typ: AUDIT_SEAL_TYPE, ...params.seal };
    const encoded = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
    const signature = await params.signer.sign(Buffer.from(encoded, "utf8"));
    return ok(`${encoded}.${Buffer.from(signature).toString("base64url")}`);
  } catch (error) {
    return err({ code: "SIGNING_FAILED", reason: errorMessage(error) });
  }
}

function isAuditSeal(value: unknown): value is AuditSeal {
  if (typeof value !== "object" || value === null) return false;
  const seal = value as Record<string, unknown>;
  return (
    seal.typ === AUDIT_SEAL_TYPE &&
    typeof seal.log === "string" &&
    seal.log.length > 0 &&
    isSeq(seal.seq) &&
    typeof seal.headHash === "string" &&
    HEX_32_BYTES.test(seal.headHash) &&
    typeof seal.sealedAt === "string"
  );
}

/** Verifies one seal locally against the audit service's key; it must name `log`. */
export function verifyAuditSeal(params: {
  readonly seal: string;
  readonly publicKey: Uint8Array;
  readonly log: string;
}): Result<AuditSeal, VerifyAuditSealError> {
  const parts = params.seal.split(".");
  if (parts.length !== 2) {
    return err({ code: "MALFORMED_SEAL", reason: "expected exactly one '.' separator" });
  }
  const [encoded, encodedSignature] = parts as [string, string];
  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch (error) {
    return err({ code: "MALFORMED_SEAL", reason: errorMessage(error) });
  }
  if (!isAuditSeal(claims)) {
    return err({ code: "MALFORMED_SEAL", reason: "seal missing required fields" });
  }
  // The signature first: a forged seal must not learn anything from a WRONG_LOG answer.
  const signature = Buffer.from(encodedSignature, "base64url");
  if (!verify(signature, Buffer.from(encoded, "utf8"), params.publicKey)) {
    return err({ code: "SIGNATURE_INVALID" });
  }
  if (claims.log !== params.log) return err({ code: "WRONG_LOG" });
  return ok(claims);
}

/**
 * Checks a served log end to end (ADR 0017 §5): entries run 1..n with nothing
 * missing, each served payload matches its hash and is a record, the chain is
 * recomputed from the genesis hash, every seal verifies, and the log matches
 * every seal: the entry at `seal.seq` exists (else `TRUNCATED`) and its hash
 * is the sealed head (else `DIVERGED`). Pass the seal the service served
 * together with any the caller already trusts (one remembered from an earlier
 * check, or one read from outside the database): a log shortened or rebuilt
 * after those were made fails against them.
 */
export function verifyAuditLedger(params: {
  readonly entries: readonly unknown[];
  readonly seals: readonly string[];
  readonly publicKey: Uint8Array;
  readonly log: string;
}): Result<VerifiedAuditLedger, VerifyAuditLedgerError> {
  const hashes: string[] = [];
  const records: { seq: number; record: AuditRecord }[] = [];
  let prevHash = AUDIT_GENESIS_HASH;

  for (const [index, value] of params.entries.entries()) {
    if (typeof value !== "object" || value === null) {
      return err({ code: "MALFORMED_ENTRY", index, reason: "not an object" });
    }
    const entry = value as Record<string, unknown>;
    if (!isSeq(entry.seq)) {
      return err({ code: "MALFORMED_ENTRY", index, reason: "seq is not a positive integer" });
    }
    if (typeof entry.payloadHash !== "string" || !HEX_32_BYTES.test(entry.payloadHash)) {
      return err({ code: "MALFORMED_ENTRY", index, reason: "payloadHash is not a SHA-256 hex" });
    }
    if (entry.payload !== undefined && typeof entry.payload !== "string") {
      return err({ code: "MALFORMED_ENTRY", index, reason: "payload is not a string" });
    }
    const seq = entry.seq;
    if (seq !== index + 1) {
      return err({ code: "SEQUENCE_GAP", expected: index + 1, found: seq });
    }
    if (entry.payload !== undefined) {
      if (computeAuditPayloadHash(entry.payload) !== entry.payloadHash) {
        return err({ code: "PAYLOAD_MISMATCH", seq });
      }
      let record: unknown;
      try {
        record = JSON.parse(entry.payload);
      } catch {
        return err({ code: "MALFORMED_RECORD", seq });
      }
      if (!isAuditRecord(record)) return err({ code: "MALFORMED_RECORD", seq });
      records.push({ seq, record });
    }
    prevHash = computeAuditEntryHash({ seq, prevHash, payloadHash: entry.payloadHash });
    hashes.push(prevHash);
  }

  let newestSeal: AuditSeal | undefined;
  for (const sealEnvelope of params.seals) {
    const verified = verifyAuditSeal({
      seal: sealEnvelope,
      publicKey: params.publicKey,
      log: params.log,
    });
    if (!verified.ok) return err({ code: "SEAL_INVALID", error: verified.error });
    const seal = verified.value;
    const atSeal = hashes[seal.seq - 1];
    if (atSeal === undefined) {
      return err({ code: "TRUNCATED", sealSeq: seal.seq, headSeq: hashes.length });
    }
    if (atSeal !== seal.headHash) return err({ code: "DIVERGED", seq: seal.seq });
    if (newestSeal === undefined || seal.seq > newestSeal.seq) newestSeal = seal;
  }

  return ok({
    records,
    headSeq: hashes.length,
    ...(newestSeal === undefined ? {} : { newestSeal }),
    unsealedCount: hashes.length - (newestSeal?.seq ?? 0),
  });
}

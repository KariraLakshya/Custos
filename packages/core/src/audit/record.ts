import { verify } from "../crypto/ed25519.js";
import { err, ok, type Result } from "../result.js";

/**
 * Who made a control-plane call (ADR 0008 §7): an operator or a Custos
 * service, identified by its API key's id. Never the key itself.
 */
export interface AuditPrincipal {
  readonly kind: "operator" | "service";
  readonly id: string;
  readonly name: string;
}

/**
 * A signed, append-only record of one action (CLAUDE.md section 10:
 * "every audit record carries the agent identity, the authority chain it
 * acted under, the data categories touched, the policy applied, the
 * decision, and a signature").
 *
 * Two kinds, one shape. An **agent action** has `agentDid` and `tool`, and
 * `authorityChain` is `[agentDid]`: flat today because no delegation exists
 * yet (Phase 6); a delegation chain extends the array without changing the
 * shape. A **control-plane action** (ADR 0008 §7) has a `principal`, the
 * operator or service that acted, and `authorityChain` is `[]` because no
 * agent acted; `agentDid` and `tool` name what it acted on, when anything.
 * Every record names an actor: an `agentDid`, a `principal`, or both.
 */
export interface AuditRecord {
  readonly agentDid?: string;
  readonly principal?: AuditPrincipal;
  readonly authorityChain: readonly string[];
  readonly tool?: string;
  readonly action: string;
  readonly dataCategories: readonly string[];
  readonly policy: { readonly rule: string; readonly decision: "allow" | "deny" };
  readonly reason?: string;
  readonly recordedAt: string;
}

/**
 * KMS-shaped signing callback, identical in shape to `TombstoneSigner` and
 * `ScopedTokenSigner` (CLAUDE.md section 4): never exposes private key
 * material.
 */
export interface AuditRecordSigner {
  readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
}

export type IssueAuditRecordError = { readonly code: "SIGNING_FAILED"; readonly reason: string };

export type VerifyAuditRecordError =
  | { readonly code: "MALFORMED_RECORD"; readonly reason: string }
  | { readonly code: "SIGNATURE_INVALID" };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isAuditPrincipal(value: unknown): value is AuditPrincipal {
  if (typeof value !== "object" || value === null) return false;
  const principal = value as Record<string, unknown>;
  return (
    (principal.kind === "operator" || principal.kind === "service") &&
    isNonEmptyString(principal.id) &&
    isNonEmptyString(principal.name)
  );
}

function isAuditRecord(value: unknown): value is AuditRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  if (record.agentDid !== undefined && !isNonEmptyString(record.agentDid)) return false;
  if (record.principal !== undefined && !isAuditPrincipal(record.principal)) return false;
  // Every record names who acted.
  if (record.agentDid === undefined && record.principal === undefined) return false;
  if (!isStringArray(record.authorityChain)) return false;
  if (record.tool !== undefined && !isNonEmptyString(record.tool)) return false;
  if (typeof record.action !== "string" || record.action.length === 0) return false;
  if (!isStringArray(record.dataCategories)) return false;
  if (typeof record.recordedAt !== "string") return false;
  if (record.reason !== undefined && typeof record.reason !== "string") return false;
  const policy = record.policy;
  if (typeof policy !== "object" || policy === null) return false;
  const policyFields = policy as Record<string, unknown>;
  if (typeof policyFields.rule !== "string") return false;
  if (policyFields.decision !== "allow" && policyFields.decision !== "deny") return false;
  return true;
}

/**
 * Signs a compact envelope — base64url(record JSON) + "." +
 * base64url(signature) — the same shape as a scoped token or revocation
 * tombstone (docs/adr/0003-scoped-token-format.md), so all three share one
 * verify path shape. Deliberately carries no expiry: an audit record is a
 * permanent statement about what already happened.
 */
export async function issueAuditRecord(params: {
  readonly record: AuditRecord;
  readonly signer: AuditRecordSigner;
}): Promise<Result<string, IssueAuditRecordError>> {
  try {
    const encodedRecord = Buffer.from(JSON.stringify(params.record), "utf8").toString("base64url");
    const signature = await params.signer.sign(Buffer.from(encodedRecord, "utf8"));
    const encodedSignature = Buffer.from(signature).toString("base64url");
    return ok(`${encodedRecord}.${encodedSignature}`);
  } catch (error) {
    return err({ code: "SIGNING_FAILED", reason: errorMessage(error) });
  }
}

/**
 * Verifies an audit record entirely locally against a caller-supplied public
 * key — no network, no database. Fails closed: a malformed envelope or a bad
 * signature is rejected, never thrown, because an auditor trusting an
 * unverified record would defeat the point of signing it at all.
 */
export function verifyAuditRecord(params: {
  readonly record: string;
  readonly publicKey: Uint8Array;
}): Result<AuditRecord, VerifyAuditRecordError> {
  const { record, publicKey } = params;
  const parts = record.split(".");
  if (parts.length !== 2) {
    return err({ code: "MALFORMED_RECORD", reason: "expected exactly one '.' separator" });
  }
  const [encodedRecord, encodedSignature] = parts as [string, string];

  let parsed: AuditRecord;
  try {
    const decoded: unknown = JSON.parse(Buffer.from(encodedRecord, "base64url").toString("utf8"));
    if (!isAuditRecord(decoded)) {
      return err({ code: "MALFORMED_RECORD", reason: "record missing required fields" });
    }
    parsed = decoded;
  } catch (error) {
    return err({ code: "MALFORMED_RECORD", reason: errorMessage(error) });
  }

  const signature = Buffer.from(encodedSignature, "base64url");
  const signedData = Buffer.from(encodedRecord, "utf8");
  if (!verify(signature, signedData, publicKey)) {
    return err({ code: "SIGNATURE_INVALID" });
  }

  return ok(parsed);
}

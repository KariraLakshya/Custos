import type { AuditLogError } from "./audit-log.js";

/**
 * Why `custos audit-log` could not call the record verified, in words
 * (ADR 0022 §6). Three kinds, matching the dashboard's Proof view:
 *
 * - `tampered`: the record itself is wrong. Someone changed, removed or
 *   rewrote entries, or a seal does not check out.
 * - `cannot-check`: nothing is known to be wrong, but the check could not be
 *   done (a service or store did not answer).
 * - `needs-a-person`: a seal key this machine has not trusted; a person
 *   compares it once.
 *
 * Only numbers from the error are printed. Its free-text reasons come from a
 * service or the network and stay in the JSON on stdout.
 */
export interface AuditFailureWords {
  readonly kind: "tampered" | "cannot-check" | "needs-a-person";
  readonly meaning: string;
  readonly nextStep: string;
  /** The code, with the seal's own code after a slash when there is one. */
  readonly code: string;
}

const KEEP_AS_IS =
  "Do not delete or repair anything. Keep the audit database as it is and tell whoever is responsible for security.";
const CHECK_KEY = "Compare the key with whoever runs the audit service; see the lines below.";

const tampered = (code: string, meaning: string): AuditFailureWords => ({
  kind: "tampered",
  meaning,
  nextStep: KEEP_AS_IS,
  code,
});
const cannotCheck = (code: string, meaning: string, nextStep: string): AuditFailureWords => ({
  kind: "cannot-check",
  meaning,
  nextStep,
  code,
});
const needsAPerson = (code: string): AuditFailureWords => ({
  kind: "needs-a-person",
  meaning: "The record is sealed with a key this machine has not trusted yet.",
  nextStep: CHECK_KEY,
  code,
});

export function auditFailureWords(error: AuditLogError): AuditFailureWords {
  switch (error.code) {
    case "UNREACHABLE":
      return cannotCheck(
        error.code,
        "The audit service did not answer, so the record could not be checked.",
        "Check that Custos is running, then run: custos audit-log",
      );
    case "BAD_RESPONSE":
      return cannotCheck(
        error.code,
        "The audit service's answer was not in the shape this command expects.",
        "Check that the audit service and the custos command are the same version.",
      );
    case "SEAL_STORE_UNREACHABLE":
      return cannotCheck(
        error.code,
        "The separate store of seals could not be read, so the newest entries could not be checked.",
        "Check CUSTOS_AUDIT_SEAL_STORE_URL and that the seal store is running.",
      );
    case "DELEGATION_UNCHECKABLE":
      return cannotCheck(
        error.code,
        "The identity service's key could not be read, so the hand-offs between agents could not be checked.",
        "Check that the identity service is running and that --identity-issuer is its DID.",
      );
    case "KEY_CHANGED":
      return needsAPerson(error.code);
    case "SEAL_INVALID":
      if (error.error.code === "UNTRUSTED_KEY") {
        return needsAPerson(`${error.code}/${error.error.code}`);
      }
      return tampered(
        `${error.code}/${error.error.code}`,
        "A seal on the record does not check out: it is damaged, belongs to another record, or was not signed by a trusted key.",
      );
    case "SEQUENCE_GAP":
      return tampered(
        error.code,
        `An entry is missing: entry #${error.expected} should be there and is not.`,
      );
    case "PAYLOAD_MISMATCH":
      return tampered(error.code, `Entry #${error.seq} was changed after it was written.`);
    case "TRUNCATED":
      return tampered(
        error.code,
        `The newest entries were deleted: a seal covers up to entry #${error.sealSeq}, but the record stops at #${error.headSeq}.`,
      );
    case "DIVERGED":
      return tampered(
        error.code,
        `The record was rewritten: entry #${error.seq} is not the one that was sealed.`,
      );
    case "MALFORMED_ENTRY":
      return tampered(error.code, "An entry is not in the shape Custos writes.");
    case "MALFORMED_RECORD":
      return tampered(error.code, `Entry #${error.seq} is not in the shape Custos writes.`);
    case "DELEGATION_INVALID":
      return tampered(
        error.code,
        `Entry #${error.seq} says one agent acted for another, but the signed hand-off behind it does not check out.`,
      );
    case "DELEGATION_UNLINKED":
      return tampered(
        error.code,
        `Entry #${error.seq} says one agent acted for another, but no checked hand-off is recorded for it.`,
      );
  }
}

const HEADLINE = {
  tampered: "Tampered",
  "cannot-check": "Cannot check",
  "needs-a-person": "Needs a person",
} as const;

/** The three stderr lines `custos audit-log` prints when the record is not verified. */
export function explainAuditFailure(error: AuditLogError): string {
  const words = auditFailureWords(error);
  return [
    `${HEADLINE[words.kind]}: ${words.meaning}`,
    `Next: ${words.nextStep}`,
    `Code: ${words.code}`,
    "",
  ].join("\n");
}

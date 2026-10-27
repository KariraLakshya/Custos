import {
  multibaseToPublicKey,
  verifyAuditLedger,
  type DidWebDocument,
  type VerifiedAuditLedger,
  type VerifyAuditLedgerError,
} from "@custos/core";

export type PullAuditLedgerError =
  | { readonly code: "UNREACHABLE"; readonly reason: string }
  | { readonly code: "BAD_RESPONSE"; readonly reason: string }
  /** The outside seal store was configured but could not be read: fail closed. */
  | { readonly code: "SEAL_STORE_UNREACHABLE"; readonly reason: string }
  | VerifyAuditLedgerError;

export interface PulledAuditLedger extends VerifiedAuditLedger {
  /** The audit log's DID. */
  readonly log: string;
  /** The seal the service served, to keep for the next check (ADR 0017 §5). */
  readonly servedSeal: string | null;
  /** How many seals from outside the database were checked; undefined when none were asked for. */
  readonly outsideSealCount?: number;
}

/**
 * Pulls the audit ledger and verifies it as an auditor would (ADR 0017):
 * the key comes from the audit service's own DID document, and the chain is
 * checked against the seal it serves **and** every seal `heldSeals` returns
 * for this log (named by its DID): ones the caller kept from earlier checks or
 * read from outside the database. A log shortened or rewritten since those
 * were made fails here.
 *
 * `outsideSeals` reads copies kept outside the audit database (ADR 0017 part
 * 2a). They are read **before** the ledger: a copy made after the ledger was
 * read would cover an entry the response lacks. A failure to read them fails
 * the whole check, never a quiet pass without them.
 */
export async function pullAuditLedger(params: {
  readonly auditUrl: string;
  readonly agentDid?: string;
  readonly heldSeals?: (log: string) => readonly string[];
  readonly outsideSeals?: (log: string) => Promise<readonly string[]>;
  readonly fetch?: typeof fetch;
}): Promise<{ ok: true; value: PulledAuditLedger } | { ok: false; error: PullAuditLedgerError }> {
  const doFetch = params.fetch ?? fetch;
  let didDocument: DidWebDocument;
  let body: { entries?: unknown; seal?: unknown };
  let outside: readonly string[] | undefined;
  try {
    const didResponse = await doFetch(new URL("/.well-known/did.json", params.auditUrl));
    if (!didResponse.ok) {
      return bad(`DID document: HTTP ${didResponse.status}`);
    }
    didDocument = (await didResponse.json()) as DidWebDocument;
    if (typeof didDocument?.id !== "string") return bad("DID document has no id");
    if (params.outsideSeals !== undefined) {
      try {
        outside = await params.outsideSeals(didDocument.id);
      } catch (error) {
        return {
          ok: false,
          error: {
            code: "SEAL_STORE_UNREACHABLE",
            reason: error instanceof Error ? error.message : String(error),
          },
        };
      }
    }
    const recordsUrl = new URL("/records", params.auditUrl);
    if (params.agentDid !== undefined) recordsUrl.searchParams.set("agentId", params.agentDid);
    const recordsResponse = await doFetch(recordsUrl);
    if (!recordsResponse.ok) return bad(`records: HTTP ${recordsResponse.status}`);
    body = (await recordsResponse.json()) as typeof body;
  } catch (error) {
    return {
      ok: false,
      error: {
        code: "UNREACHABLE",
        reason: error instanceof Error ? error.message : String(error),
      },
    };
  }

  const multibase = didDocument?.verificationMethod?.[0]?.publicKeyMultibase;
  const key = typeof multibase === "string" ? multibaseToPublicKey(multibase) : undefined;
  if (key === undefined || !key.ok) return bad("DID document has no readable key");
  if (!Array.isArray(body.entries)) return bad("records: no entries");
  if (body.seal !== null && typeof body.seal !== "string") return bad("records: malformed seal");

  const servedSeal = body.seal;
  const verified = verifyAuditLedger({
    entries: body.entries,
    seals: [
      ...(servedSeal === null ? [] : [servedSeal]),
      ...(params.heldSeals?.(didDocument.id) ?? []),
      ...(outside ?? []),
    ],
    publicKey: key.value,
    log: didDocument.id,
  });
  if (!verified.ok) return verified;
  return {
    ok: true,
    value: {
      ...verified.value,
      log: didDocument.id,
      servedSeal,
      ...(outside === undefined ? {} : { outsideSealCount: outside.length }),
    },
  };
}

function bad(reason: string): { ok: false; error: PullAuditLedgerError } {
  return { ok: false, error: { code: "BAD_RESPONSE", reason } };
}

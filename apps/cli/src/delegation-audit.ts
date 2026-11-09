import {
  didWebToResolutionUrl,
  handOffHash,
  verifyDelegationChain,
  type AuditRecord,
  type DelegationLimits,
  type DidWebDocument,
} from "@custos/core";

/**
 * The widest limits any vault can be configured to (its env bounds:
 * `DELEGATION_MAX_LINKS` ≤ 15, `DELEGATION_MAX_LIFETIME_SECONDS` ≤ 1 day,
 * `DELEGATION_MAX_BYTES` ≤ 256 KiB, `VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS` ≤ 300),
 * so a chain a vault genuinely accepted is never refused here. The vault
 * enforced its own, possibly tighter, limits when it issued the token; this
 * re-check proves the signatures, links and narrowing, not the vault's config.
 */
export const AUDIT_DELEGATION_LIMITS: DelegationLimits = {
  maxLinks: 15,
  maxLifetimeSeconds: 86_400,
  maxBytes: 262_144,
  maxClockSkewSeconds: 300,
};

/** One delegated entry, re-verified: its chain as a person reads it. */
export interface CheckedDelegation {
  readonly seq: number;
  /** "issued" carries the evidence; "call" is linked to an issued entry. */
  readonly kind: "issued" | "call";
  /** "<operator> → <first delegator> → … → <agent>". */
  readonly chain: string;
}

export type DelegationAuditError =
  /** An entry's chain evidence does not verify, or does not match what the entry says. */
  | { readonly code: "DELEGATION_INVALID"; readonly seq: number; readonly reason: string }
  /** An entry names a chain with no verified issuance entry behind it. */
  | { readonly code: "DELEGATION_UNLINKED"; readonly seq: number }
  /** The pinned identity issuer's document could not be read, so no chain could be checked. */
  | { readonly code: "DELEGATION_UNCHECKABLE"; readonly reason: string };

/**
 * Resolves the pinned identity issuer's DID document over HTTP, once per
 * check. Only the document comes over the network; the chain check itself is
 * local (ADR 0020 §3). The DID is pinned by the auditor, never read from an
 * entry, so an entry cannot vouch for itself.
 */
export async function resolvePinnedIssuer(
  did: string,
  fetchImpl: typeof fetch = fetch,
): Promise<DidWebDocument> {
  const url = didWebToResolutionUrl(did);
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(5_000) });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  const document = (await response.json()) as Partial<DidWebDocument> | null;
  if (document?.id !== did) {
    throw new Error(`${url}: document names ${String(document?.id)}, expected ${did}`);
  }
  return document as DidWebDocument;
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((item, i) => item === b[i]);
}

function display(record: AuditRecord, root: string): string {
  return [root, ...record.authorityChain].join(" → ");
}

type Entry = { readonly seq: number; readonly record: AuditRecord };

/**
 * Re-verifies every delegated entry in a ledger that has already verified
 * (ADR 0020 §6): an issuance entry's evidence is checked offline against the
 * pinned identity issuer at the vault's recorded time of the check, and must
 * name the same chain, agent, tool and action as the entry; each call entry
 * must link, by its reference, to such an issuance entry for the same agent,
 * chain, tool and action. Any failure fails the whole check, like an edited
 * payload. Entries without a chain are not touched. The issuer's document is
 * resolved only when there is a delegated entry to check.
 */
export async function checkDelegations(params: {
  readonly records: readonly Entry[];
  readonly issuerDid: string;
  readonly resolveIssuer: (did: string) => Promise<DidWebDocument>;
}): Promise<
  | { readonly ok: true; readonly checked: readonly CheckedDelegation[] }
  | { readonly ok: false; readonly error: DelegationAuditError }
> {
  const delegated = params.records.filter(
    ({ record }) => record.delegationRef !== undefined || record.authorityChain.length > 1,
  );
  if (delegated.length === 0) return { ok: true, checked: [] };

  let document: DidWebDocument;
  try {
    document = await params.resolveIssuer(params.issuerDid);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { ok: false, error: { code: "DELEGATION_UNCHECKABLE", reason } };
  }

  // Issuance entries first, so a call can be matched to one. One hand-off
  // can cover several tools and actions, and each token is for one of them,
  // so the reference alone does not pick the issuance entry.
  const keyOf = (record: AuditRecord) =>
    JSON.stringify([record.delegationRef, record.agentDid, record.tool, record.action]);
  const issued = new Map<string, { record: AuditRecord; root: string }>();
  const checked: CheckedDelegation[] = [];
  for (const { seq, record } of delegated) {
    const evidence = record.delegation;
    if (evidence === undefined) continue;
    const invalid = (reason: string) =>
      ({ ok: false, error: { code: "DELEGATION_INVALID", seq, reason } }) as const;
    if (record.agentDid === undefined || record.tool === undefined) {
      return invalid("a delegated entry must name its agent and tool");
    }
    const checkedAt = new Date(evidence.checkedAt);
    const recordedAt = new Date(record.recordedAt);
    if (Number.isNaN(checkedAt.getTime()) || Number.isNaN(recordedAt.getTime())) {
      return invalid("unreadable time");
    }
    // The vault checks, then reports at once: its time is the audit
    // service's, give or take clock skew. `recordedAt` is the audit service's
    // own and sealed; `checkedAt` is only the reporter's word, so it may not
    // move far from it either way (a backdated one would revive an expired chain).
    const skewMs = AUDIT_DELEGATION_LIMITS.maxClockSkewSeconds * 1000;
    if (checkedAt.getTime() > recordedAt.getTime() + skewMs) {
      return invalid("checked after it was recorded");
    }
    if (checkedAt.getTime() < recordedAt.getTime() - skewMs) {
      return invalid("checked long before it was recorded");
    }
    const verified = await verifyDelegationChain({
      chain: { handOffs: evidence.handOffs, credentials: evidence.credentials },
      requesterDid: record.agentDid,
      request: { tool: record.tool, action: record.action },
      issuer: { did: params.issuerDid, document },
      now: checkedAt,
      limits: AUDIT_DELEGATION_LIMITS,
    });
    if (!verified.ok) return invalid(verified.error.code);
    if (!sameList(verified.value.dids, record.authorityChain)) {
      return invalid("the entry's authority chain is not the chain its evidence proves");
    }
    const last = evidence.handOffs[evidence.handOffs.length - 1]!;
    if (handOffHash(last) !== record.delegationRef) {
      return invalid("the entry's reference is not its evidence's");
    }
    const via = evidence.root.via === undefined ? "" : `, ${evidence.root.via}`;
    const root = `${evidence.root.name} (${evidence.root.kind}${via})`;
    issued.set(keyOf(record), { record, root });
    checked.push({ seq, kind: "issued", chain: display(record, root) });
  }

  for (const { seq, record } of delegated) {
    if (record.delegation !== undefined) continue;
    const match = record.delegationRef === undefined ? undefined : issued.get(keyOf(record));
    if (match === undefined || !sameList(match.record.authorityChain, record.authorityChain)) {
      return { ok: false, error: { code: "DELEGATION_UNLINKED", seq } };
    }
    checked.push({ seq, kind: "call", chain: display(record, match.root) });
  }

  checked.sort((x, y) => x.seq - y.seq);
  return { ok: true, checked };
}

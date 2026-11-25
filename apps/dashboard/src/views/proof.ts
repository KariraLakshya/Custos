import type { AuditRecord } from "@custos/core";
import { eventSentence, principalLabel } from "@custos/contracts";
import { escapeHtml, type Escaped } from "./escape.js";
import {
  agentsOf,
  CHECKING,
  clock,
  didText,
  forbidden,
  labeller,
  type AgentsAnswer,
  type LedgerCheck,
  type Panel,
  type Source,
} from "./inputs.js";

/**
 * The _Proof_ view (dashboard plan, screen 3): "What happened, and can I
 * prove it?". The verdict is the one `custos audit-log` reaches, from the
 * same check (`@custos/audit-client/ledger`); every event is one sentence.
 */

type Verified = Extract<LedgerCheck, { ok: true }>;

export type LedgerVerdict =
  | { readonly kind: "loading" }
  | { readonly kind: "forbidden" }
  | { readonly kind: "verified"; readonly check: Verified }
  | {
      readonly kind: "tampered" | "needs-a-person" | "cannot-check";
      readonly meaning: string;
      readonly nextStep: string;
      readonly code: string;
    };

const KEEP_AS_IS =
  "Do not delete or repair anything. Keep the audit database as it is and tell whoever is responsible for security.";
const INDEPENDENT = "For an independent check, run: custos audit-log";

/** The Proof result for a ledger read, in the three kinds `custos audit-log` uses. */
export function ledgerVerdict(source: Source<LedgerCheck>): LedgerVerdict {
  if (source.state === "loading") return { kind: "loading" };
  if (source.state === "forbidden") return { kind: "forbidden" };
  const cannotCheck = (code: string, meaning: string, nextStep: string): LedgerVerdict => ({
    kind: "cannot-check",
    meaning,
    nextStep,
    code,
  });
  if (source.state === "failed") {
    return cannotCheck(
      "UNREACHABLE",
      "The audit service is not answering, so the record cannot be checked right now.",
      "Check that the audit service is running.",
    );
  }
  const check = source.data;
  if (check.ok) return { kind: "verified", check };
  const tampered = (code: string, meaning: string): LedgerVerdict => ({
    kind: "tampered",
    meaning,
    nextStep: KEEP_AS_IS,
    code,
  });
  const error = check.error;
  switch (error.code) {
    case "UNREACHABLE":
      return cannotCheck(
        error.code,
        "The audit service is not answering, so the record cannot be checked right now.",
        "Check that the audit service is running.",
      );
    case "BAD_RESPONSE":
      if (error.status === 401 || error.status === 403) return { kind: "forbidden" };
      return cannotCheck(
        error.code,
        "The audit service's answer was not in the shape the dashboard expects.",
        "Check that the audit service and the dashboard are the same version.",
      );
    case "SEAL_STORE_UNREACHABLE":
      return cannotCheck(
        error.code,
        "The separate store of seals could not be read, so the newest entries could not be checked.",
        "Check that the seal store is running.",
      );
    case "DELEGATION_UNCHECKABLE":
      return cannotCheck(
        error.code,
        "The identity service's key could not be read, so the hand-offs between agents could not be checked.",
        "Check that the identity service is running.",
      );
    case "SEAL_INVALID":
      if (error.error.code === "UNTRUSTED_KEY") {
        return {
          kind: "needs-a-person",
          meaning:
            "The record is now sealed with a key the dashboard has not seen before. It may be a planned key change, or not.",
          nextStep:
            "Run custos audit-log; it shows the new key and how to accept it with --accept-key once you have confirmed it with whoever runs the audit service. Restarting the dashboard makes it trust the new key.",
          code: `${error.code}/${error.error.code}`,
        };
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
      return tampered(error.code, `Entry #${error.seq} does not match its seal.`);
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

/** Who each delegated chain starts from, by `delegationRef`, from the issuance entries. */
export function chainRoots(
  records: readonly { readonly record: AuditRecord }[],
): ReadonlyMap<string, string> {
  const roots = new Map<string, string>();
  for (const { record } of records) {
    if (record.delegation !== undefined && record.delegationRef !== undefined) {
      roots.set(record.delegationRef, principalLabel(record.delegation.root));
    }
  }
  return roots;
}

/** Who cut each agent off, from the verified log's newest allowed `agents.revoke` entry. */
export function revokers(
  records: readonly { readonly seq: number; readonly record: AuditRecord }[],
): ReadonlyMap<string, string> {
  const by = new Map<string, string>();
  for (const { record } of [...records].sort((a, b) => a.seq - b.seq)) {
    if (
      record.action === "agents.revoke" &&
      record.policy.decision === "allow" &&
      record.agentDid !== undefined
    ) {
      by.set(record.agentDid, principalLabel(record.principal));
    }
  }
  return by;
}

/** One entry as one sentence, with names where identity knows them. */
export function sentenceOf(
  record: AuditRecord,
  label: (did: string) => string,
  roots: ReadonlyMap<string, string>,
): string {
  const root = record.delegationRef === undefined ? undefined : roots.get(record.delegationRef);
  return eventSentence(record, {
    agent: label,
    ...(root === undefined ? {} : { chainRoot: root }),
  });
}

// JSON leaves these raw; on a page they can reorder or hide text.
const INVISIBLE = new RegExp(
  `[${[
    [0x7f, 0x9f], // DEL and the C1 controls
    [0x200e, 0x200f], // direction marks
    [0x2028, 0x2029], // line and paragraph separators
    [0x202a, 0x202e], // bidi embeddings and overrides
    [0x2066, 0x2069], // bidi isolates
  ]
    .map(([from, to]) => `${String.fromCodePoint(from!)}-${String.fromCodePoint(to!)}`)
    .join("")}]`,
  "g",
);

function rawText(record: AuditRecord): Escaped {
  const json = JSON.stringify(record, null, 2).replace(
    INVISIBLE,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  return escapeHtml(json);
}

export interface ProofEntry {
  readonly seq: number;
  readonly time: Escaped;
  readonly sentence: Escaped;
  /** Shown on a click: the record as it was sealed. */
  readonly raw: Escaped;
  readonly agentDid: string | undefined;
}

export interface ProofView {
  readonly result: {
    readonly tone: "green" | "red" | "grey";
    readonly icon: "✓" | "✗" | "!" | "…" | "";
    readonly headline: Escaped;
    readonly lines: readonly Escaped[];
  };
  /** Newest first, narrowed to `agentDid` when one is chosen. */
  readonly entries: Panel<{
    readonly items: readonly ProofEntry[];
    readonly empty: Escaped | undefined;
  }>;
  /** The agents the filter offers, by name. */
  readonly filter: readonly { readonly did: Escaped; readonly label: Escaped }[];
}

export function proofView(input: {
  readonly ledger: Source<LedgerCheck>;
  readonly agents: Source<AgentsAnswer>;
  /** Narrow the list to one agent (DONE point 2: proof for the agent that was cut off). */
  readonly agentDid?: string;
}): ProofView {
  const verdict = ledgerVerdict(input.ledger);
  const agents = input.agents.state === "ok" ? agentsOf(input.agents.data) : undefined;
  const label = labeller(agents);
  const filter = [...(agents?.values() ?? [])].map((agent) => ({
    did: didText(agent.did),
    label: escapeHtml(agent.label),
  }));

  switch (verdict.kind) {
    case "loading":
      return {
        result: { tone: "grey", icon: "…", headline: CHECKING, lines: [] },
        entries: { state: "loading", text: CHECKING },
        filter,
      };
    case "forbidden":
      return {
        result: {
          tone: "grey",
          icon: "",
          headline: escapeHtml("Your group cannot see the audit record."),
          lines: [escapeHtml("Ask whoever runs Custos.")],
        },
        entries: forbidden("the audit record"),
        filter,
      };
    case "verified":
      break;
    default: {
      const headline = {
        tampered: "✗ Tampered",
        "needs-a-person": "! Needs a person",
        "cannot-check": "Cannot check right now",
      }[verdict.kind];
      return {
        result: {
          tone: "red",
          icon: verdict.kind === "tampered" ? "✗" : "!",
          headline: escapeHtml(headline),
          lines: [verdict.meaning, `Next: ${verdict.nextStep}`, `Code: ${verdict.code}`].map(
            escapeHtml,
          ),
        },
        // A record that did not verify shows none of its entries.
        entries: {
          state: "unreadable",
          tone: "red",
          text: escapeHtml(
            verdict.kind === "cannot-check"
              ? "The entries cannot be shown until the record can be checked."
              : "The entries are not shown, because the record did not verify.",
          ),
        },
        filter,
      };
    }
  }

  const { ledger } = verdict.check;
  const roots = chainRoots(ledger.records);
  const sealed = ledger.newestSeal;
  const lines = [
    `${ledger.headSeq} ${ledger.headSeq === 1 ? "entry" : "entries"} · none changed since they were sealed`,
    sealed === undefined
      ? "not sealed yet"
      : `last sealed ${clock(sealed.sealedAt)}` +
        (ledger.unsealedCount === 0
          ? ""
          : ` · ${ledger.unsealedCount} newer ${ledger.unsealedCount === 1 ? "entry" : "entries"} not sealed yet`),
    `The dashboard checks this itself and starts fresh when it restarts. ${INDEPENDENT}`,
  ];
  const items = ledger.records
    .filter(({ record }) => input.agentDid === undefined || record.agentDid === input.agentDid)
    .map(({ seq, record }) => ({
      seq,
      time: escapeHtml(clock(record.recordedAt)),
      sentence: escapeHtml(sentenceOf(record, label, roots)),
      raw: rawText(record),
      agentDid: record.agentDid,
    }))
    .sort((a, b) => b.seq - a.seq);
  return {
    result: {
      tone: "green",
      icon: "✓",
      headline: escapeHtml("✓ Verified"),
      lines: lines.map(escapeHtml),
    },
    entries: {
      state: "ok",
      data: {
        items,
        empty:
          items.length > 0
            ? undefined
            : escapeHtml(
                ledger.headSeq === 0
                  ? "No entries yet. The first one appears when an agent makes a call."
                  : "No entries for this agent.",
              ),
      },
    },
    filter,
  };
}

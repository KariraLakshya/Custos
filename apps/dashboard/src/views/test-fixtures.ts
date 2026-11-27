// Test support: loads a recorded fixture (apps/dashboard/fixtures, written by
// scripts/record-fixtures.mjs) and checks its audit log the way the back end
// will, through `@custos/audit-client/ledger`: the real fetch order against a
// fake `fetch` serving the recorded answers, then the delegation re-check.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkDelegations, pullAuditLedger } from "@custos/audit-client/ledger";
import type { DidWebDocument } from "@custos/core";
import type {
  AgentsAnswer,
  LedgerCheck,
  PoliciesAnswer,
  RevocationsAnswer,
  Source,
} from "./inputs.js";

export type FixtureName = "clean" | "tampered" | "truncated" | "delegated";

export interface Fixture {
  readonly name: FixtureName;
  readonly now: string;
  readonly auditDid: string;
  readonly identityDid: string;
  readonly didDocuments: {
    readonly audit: DidWebDocument;
    readonly identity: DidWebDocument;
    readonly revocation: DidWebDocument;
  };
  readonly audit: { readonly entries: readonly unknown[]; readonly seal: string | null };
  readonly agents: AgentsAnswer & { readonly agents: readonly Record<string, unknown>[] };
  readonly policies: PoliciesAnswer;
  readonly revocations: RevocationsAnswer;
}

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "fixtures");

export function loadFixture(name: FixtureName): Fixture {
  return JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Fixture;
}

/** Checks a fixture's log; `trustedKey` stands in for a key the dashboard pinned earlier. */
export async function checkLedger(
  fixture: Fixture,
  options: { readonly trustedKey?: string } = {},
): Promise<LedgerCheck> {
  const fakeFetch = (url: URL | string): Promise<Response> => {
    const path = new URL(String(url)).pathname;
    const body = path === "/.well-known/did.json" ? fixture.didDocuments.audit : fixture.audit;
    return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
  };
  const pulled = await pullAuditLedger({
    auditUrl: "http://localhost:4004",
    fetch: fakeFetch as typeof fetch,
    ...(options.trustedKey === undefined ? {} : { trustedKeys: () => [options.trustedKey!] }),
  });
  if (!pulled.ok) return pulled;
  const delegations = await checkDelegations({
    records: pulled.value.records,
    issuerDid: fixture.identityDid,
    resolveIssuer: () => Promise.resolve(fixture.didDocuments.identity),
  });
  if (!delegations.ok) return delegations;
  return { ok: true, ledger: pulled.value, delegations: delegations.checked };
}

export function ok<T>(data: T, readAt = "2026-11-20T14:10:00.000Z"): Source<T> {
  return { state: "ok", data, readAt };
}

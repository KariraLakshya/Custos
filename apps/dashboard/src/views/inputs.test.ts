import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { escapeHtml, joinEscaped } from "./escape.js";
import {
  ago,
  clock,
  cutOffsOf,
  day,
  didText,
  grantsOf,
  isoTime,
  panelOf,
  within,
} from "./inputs.js";

describe("escapeHtml, the one place a string becomes safe for the page", () => {
  it("escapes the five characters that matter in content and quoted attributes", () => {
    expect(escapeHtml(`<a href="x" title='y'>&</a>`)).toBe(
      "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;",
    );
    expect(escapeHtml("billing-bot")).toBe("billing-bot");
  });

  it("joins already-escaped parts without escaping them twice", () => {
    expect(joinEscaped(escapeHtml("<"), escapeHtml("&"))).toBe("&lt;&amp;");
  });
});

describe("reading the answers", () => {
  it("isoTime accepts only ISO UTC times", () => {
    expect(isoTime("2026-11-20T14:00:00.000Z")).toBe("2026-11-20T14:00:00.000Z");
    expect(isoTime("2026-11-20T14:00:00Z")).toBe("2026-11-20T14:00:00Z");
    for (const bad of ["2026-13-45T99:99:99Z", "14:00", 5, null, "2026-11-20 14:00:00Z"]) {
      expect(isoTime(bad)).toBeUndefined();
    }
  });

  it("clock and day read UTC; clock says --:-- for a bad time", () => {
    expect(clock("2026-11-20T14:02:30.000Z")).toBe("14:02");
    expect(clock("nope")).toBe("--:--");
    expect(day("2026-11-02T23:59:00.000Z")).toBe("2 Nov");
  });

  it("ago reads seconds, minutes, hours, then a day", () => {
    const now = new Date("2026-11-20T14:00:00.000Z");
    expect(ago("2026-11-20T14:00:05.000Z", now)).toBe("0 s ago");
    expect(ago("2026-11-20T13:59:01.000Z", now)).toBe("59 s ago");
    expect(ago("2026-11-20T13:59:00.000Z", now)).toBe("1 min ago");
    expect(ago("2026-11-20T13:00:00.000Z", now)).toBe("1 h ago");
    expect(ago("2026-11-19T13:59:59.000Z", now)).toBe("on 19 Nov");
  });

  it("within is inclusive at its edge", () => {
    const now = new Date("2026-11-20T14:00:00.000Z");
    expect(within("2026-11-20T13:00:00.000Z", now, 3_600_000)).toBe(true);
    expect(within("2026-11-20T12:59:59.999Z", now, 3_600_000)).toBe(false);
  });

  it("grantsOf skips entries that are not grants", () => {
    expect(grantsOf({ grants: [null, [], { tool: "x" }] })).toEqual([]);
  });

  it("cutOffsOf drops a reason that is not plain text, and reads no tombstones as none", () => {
    const tombstone = `${Buffer.from(
      JSON.stringify({
        agentDid: "did:web:a",
        revokedAt: "2026-11-20T14:00:00.000Z",
        reason: "a\nb",
      }),
    ).toString("base64url")}.sig`;
    expect(cutOffsOf({ tombstones: [tombstone] })).toEqual([
      { agentDid: "did:web:a", revokedAt: "2026-11-20T14:00:00.000Z", reason: undefined },
    ]);
    expect(cutOffsOf({ tombstones: [] })).toEqual([]);
    expect(
      cutOffsOf({ tombstones: [`${Buffer.from("[]").toString("base64url")}.x`] }),
    ).toBeUndefined();
  });

  it("didText shows a plain DID and hides anything else", () => {
    expect(didText("did:web:a")).toBe("did:web:a");
    expect(didText("did:web:<a>\n")).toBe("(not shown)");
  });

  it("panelOf keeps a failed source's last good answer only when it can be read", () => {
    const failed = {
      state: "failed",
      service: "vault",
      lastGood: { data: 1, readAt: "x" },
    } as const;
    expect(panelOf(failed, "grants", () => undefined)).toEqual({
      state: "unreadable",
      tone: "red",
      text: "The vault service is not answering.",
    });
  });
});

const VIEWS = dirname(fileURLToPath(import.meta.url));
const IMPORT = /(?:^|\n)\s*(import|export)\s+(type\s+)?[^;]*?\bfrom\s+"([^"]+)"/g;

describe("what the view models take in (ADR 0022 §5)", () => {
  it("at run time, only @custos/contracts: no pg, no AWS SDK, no network", () => {
    const runtime = new Set<string>();
    const typeOnly = new Set<string>();
    for (const file of readdirSync(VIEWS)) {
      if (!file.endsWith(".ts") || file.endsWith(".test.ts") || file === "test-fixtures.ts")
        continue;
      for (const [, , type, specifier] of readFileSync(join(VIEWS, file), "utf8").matchAll(
        IMPORT,
      )) {
        if (specifier!.startsWith(".")) continue;
        (type === undefined ? runtime : typeOnly).add(specifier!);
      }
    }
    expect([...runtime]).toEqual(["@custos/contracts"]);
    expect([...typeOnly].sort()).toEqual(["@custos/audit-client/ledger", "@custos/core"]);
  });
});

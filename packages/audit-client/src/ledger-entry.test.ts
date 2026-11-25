import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as ledger from "./ledger-entry.js";

const SRC = dirname(fileURLToPath(import.meta.url));
const IMPORT = /(?:^|\n)\s*(?:import|export)\b[^;]*?\bfrom\s+"([^"]+)"/g;

/** Every package (bare specifier) reachable from `entry` through relative imports. */
function packagesReachedFrom(entry: string): Set<string> {
  const seen = new Set<string>();
  const packages = new Set<string>();
  const visit = (file: string) => {
    if (seen.has(file)) return;
    seen.add(file);
    for (const [, specifier] of readFileSync(file, "utf8").matchAll(IMPORT)) {
      if (specifier!.startsWith(".")) {
        visit(join(dirname(file), specifier!.replace(/\.js$/, ".ts")));
      } else {
        packages.add(specifier!);
      }
    }
  };
  visit(join(SRC, entry));
  return packages;
}

describe("@custos/audit-client/ledger (ADR 0022 §5)", () => {
  it("imports only @custos/core: no pg, no AWS SDK, no contracts", () => {
    expect([...packagesReachedFrom("ledger-entry.ts")]).toEqual(["@custos/core"]);
  });

  it("the walker does see pg and the AWS SDK behind the package root (control)", () => {
    const root = packagesReachedFrom("index.ts");
    expect(root.has("pg")).toBe(true);
    expect(root.has("@aws-sdk/client-s3")).toBe(true);
  });

  it("exports the seal check and the delegation re-check", () => {
    expect(typeof ledger.pullAuditLedger).toBe("function");
    expect(typeof ledger.checkDelegations).toBe("function");
    expect(typeof ledger.resolvePinnedIssuer).toBe("function");
    expect(ledger.AUDIT_DELEGATION_LIMITS.maxLinks).toBe(15);
  });
});

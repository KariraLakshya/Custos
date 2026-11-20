import { REFUSAL_REASONS, REFUSALS } from "@custos/contracts";
import { describe, expect, it } from "vitest";
import { escapeHtml, expandRefusals, REFUSALS_PLACEHOLDER, renderRefusals } from "./refusals.js";

describe("renderRefusals", () => {
  const page = renderRefusals();

  it("has a row for every code in the catalogue", () => {
    for (const code of Object.keys(REFUSALS)) {
      expect(page).toContain(`<tr id="${code}"> <td><code>${code}</code></td>`);
    }
  });

  it("has a row for every finer reason, under its code", () => {
    for (const [code, reasons] of Object.entries(REFUSAL_REASONS)) {
      expect(page).toContain(`## Reasons under ${code}`);
      for (const reason of Object.keys(reasons)) {
        expect(page).toContain(`<tr id="${code}-${reason}"> <td><code>${reason}</code></td>`);
      }
    }
  });

  it("labels alarms as Problem and the rest as Refused, as the CLI does", () => {
    expect(page).toMatch(/<code>REVOCATION_STATE_STALE<\/code><\/td> <td>Problem<\/td>/);
    expect(page).toMatch(/<code>POLICY_DENIED<\/code><\/td> <td>Refused<\/td>/);
  });

  it("escapes placeholders and template syntax so the page compiles", () => {
    expect(page).not.toContain("<tool>");
    expect(page).toContain("&lt;tool&gt;");
    const hostile = renderRefusals(
      { X: { severity: "normal", meaning: "{{ evil }} <script>", nextStep: "a | b `c`" } },
      {},
    );
    expect(hostile).not.toContain("{{");
    expect(hostile).not.toContain("<script>");
    expect(hostile).toContain("<code>c</code>");
    expect(hostile).toContain('<table v-pre class="custos-refusals">');
  });

  it("separates cells with a space, so the search index keeps words apart", () => {
    expect(page).not.toMatch(/<\/td><td>/);
  });

  it("keeps each table one HTML block: no blank line inside it", () => {
    const tables = page.match(/<table[\s\S]*?<\/table>/g) ?? [];
    expect(tables).toHaveLength(1 + Object.keys(REFUSAL_REASONS).length);
    for (const html of tables) expect(html).not.toMatch(/\n\s*\n/);
  });
});

describe("expandRefusals", () => {
  it("replaces the placeholder with the tables", () => {
    const out = expandRefusals(`# Codes\n\n${REFUSALS_PLACEHOLDER}\n`);
    expect(out).not.toContain(REFUSALS_PLACEHOLDER);
    expect(out).toContain("## Every code");
  });

  it("leaves a page without the placeholder alone", () => {
    expect(expandRefusals("# Other page\n")).toBe("# Other page\n");
  });
});

describe("escapeHtml", () => {
  it("escapes every character that HTML or Vue would read", () => {
    expect(escapeHtml(`&<>"'{}`)).toBe("&amp;&lt;&gt;&quot;&#39;&#123;&#125;");
  });
});

/**
 * Renders the refusal-codes reference page from the catalogue in
 * `@custos/contracts` (ADR 0022 §6), at build time, so the page cannot drift
 * from what the CLI and SDK print.
 *
 * The output is raw HTML, not Markdown: catalogue text holds `<tool>` and
 * `<agent>` placeholders, backticks and pipes, which Markdown tables and
 * VitePress's Vue compiler would otherwise read as syntax. Every string is
 * escaped, and each table carries `v-pre` so no `{{ }}` is ever evaluated.
 */
import { REFUSAL_REASONS, REFUSALS, type RefusalEntry } from "@custos/contracts";

/** The placeholder a page writes where the generated tables go. */
export const REFUSALS_PLACEHOLDER = "<!-- @custos-refusals -->";

type Catalogue = Readonly<Record<string, RefusalEntry>>;
type Reasons = Readonly<Record<string, Catalogue>>;

const ESCAPES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "{": "&#123;",
  "}": "&#125;",
};

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"'{}]/g, (char) => ESCAPES[char] ?? char);
}

/** Escapes the text, then shows `back-quoted` spans as code. */
function prose(text: string): string {
  return escapeHtml(text).replace(/`([^`]+)`/g, "<code>$1</code>");
}

function severityLabel(entry: RefusalEntry): string {
  return entry.severity === "alarm" ? "Problem" : "Refused";
}

function table(rows: readonly (readonly [string, RefusalEntry])[], idPrefix: string): string {
  const body = rows
    .map(
      ([code, entry]) =>
        // Spaces between cells: the search index strips tags, and without
        // them the last word of one cell runs into the first of the next.
        `<tr id="${escapeHtml(idPrefix + code)}"> <td><code>${escapeHtml(code)}</code></td>` +
        ` <td>${severityLabel(entry)}</td> <td>${prose(entry.meaning)}</td>` +
        ` <td>${prose(entry.nextStep)}</td> </tr>`,
    )
    .join("\n");
  // No blank line inside: Markdown ends an HTML block at a blank line.
  return [
    '<table v-pre class="custos-refusals">',
    "<thead><tr><th>Code</th><th>Shown as</th><th>What it means</th><th>What to do next</th></tr></thead>",
    "<tbody>",
    body,
    "</tbody>",
    "</table>",
  ].join("\n");
}

/** The Markdown and HTML that replace {@link REFUSALS_PLACEHOLDER}. */
export function renderRefusals(
  refusals: Catalogue = REFUSALS,
  reasons: Reasons = REFUSAL_REASONS,
): string {
  const sections = ["## Every code", "", table(Object.entries(refusals), ""), ""];
  for (const [code, underCode] of Object.entries(reasons)) {
    sections.push(
      `## Reasons under ${code}`,
      "",
      `The CLI prints these as \`Code: ${code} (REASON)\`. A reason not listed here falls back to the meaning of \`${code}\` above.`,
      "",
      table(Object.entries(underCode), `${code}-`),
      "",
    );
  }
  return sections.join("\n");
}

/** Replaces the placeholder in a page's source; any other page is returned unchanged. */
export function expandRefusals(source: string): string {
  return source.includes(REFUSALS_PLACEHOLDER)
    ? source.replace(REFUSALS_PLACEHOLDER, () => renderRefusals())
    : source;
}

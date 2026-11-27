/**
 * The one place a string becomes safe to put in the page (ADR 0022 §5). Every
 * string a view model outputs has the type `Escaped`, which only this module
 * makes, so a view cannot hand the page a raw string by mistake: names,
 * reasons and tool names all came over the network, and a name such as
 * `<script>` must be shown as text, never run.
 */
declare const escaped: unique symbol;
export type Escaped = string & { readonly [escaped]: true };

const ENTITIES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** Escapes text for HTML element content and quoted attribute values. */
export function escapeHtml(text: string): Escaped {
  return text.replace(/[&<>"']/g, (char) => ENTITIES[char] ?? char) as Escaped;
}

/** Joins strings that are already escaped; the result stays escaped. */
export function joinEscaped(...parts: readonly Escaped[]): Escaped {
  return parts.join("") as Escaped;
}

import { refusalFor } from "@custos/contracts";

// Codes and reasons come off the wire. Only this shape is printed as-is, so a
// service cannot write control characters to the terminal.
export const CODE_SHAPE = /^[A-Z][A-Z0-9_]{0,63}$/;

/**
 * A refusal in words (ADR 0022 §6): what it means, what to do next, and the
 * code for scripts and searching. "Refused" is Custos working; "Problem" is
 * something actually wrong. `fill` supplies the `<tool>` and `<agent>` a next
 * step may name; both come from this command's own arguments and files.
 */
export function explainRefusal(
  code: unknown,
  reason: unknown,
  fill: { readonly tool?: string; readonly agent?: string } = {},
): string {
  const entry = refusalFor(code, reason);
  const next = entry.nextStep
    .replaceAll("<tool>", fill.tool ?? "<tool>")
    .replaceAll("<agent>", fill.agent ?? "<agent id>");
  const shownCode = typeof code === "string" && CODE_SHAPE.test(code) ? code : "UNKNOWN";
  const shownReason = typeof reason === "string" && CODE_SHAPE.test(reason) ? ` (${reason})` : "";
  return [
    `${entry.severity === "alarm" ? "Problem" : "Refused"}: ${entry.meaning}`,
    `Next: ${next}`,
    `Code: ${shownCode}${shownReason}`,
    "",
  ].join("\n");
}

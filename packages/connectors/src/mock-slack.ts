import { err, ok } from "@custos/contracts";
import type { Connector } from "./connector.js";

export interface PostedMessage {
  readonly id: string;
  readonly channel: string;
  readonly text: string;
}

function isPostMessageInput(value: unknown): value is { channel: string; text: string } {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.channel === "string" && typeof v.text === "string";
}

/**
 * Fake Slack connector: no network calls, everything held in memory. Exists
 * to prove the vault/token pattern generalizes across more than one tool
 * (CLAUDE.md's Phase 2 "two or three tool connectors").
 */
export function createMockSlackConnector(): Connector & {
  readonly messages: readonly PostedMessage[];
} {
  const messages: PostedMessage[] = [];

  return {
    tool: "mock-slack",
    get messages() {
      return messages;
    },
    async call({ action, input }) {
      if (action !== "post-message") {
        return err({ code: "UNKNOWN_ACTION", action });
      }
      if (!isPostMessageInput(input)) {
        return err({ code: "INVALID_INPUT", reason: "expected { channel: string, text: string }" });
      }
      const message: PostedMessage = {
        id: `msg_${messages.length + 1}`,
        channel: input.channel,
        text: input.text,
      };
      messages.push(message);
      return ok(message);
    },
    async revoke() {
      // no-op: fake tool has no real access to revoke.
    },
  };
}

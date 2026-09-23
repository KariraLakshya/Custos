import { err, ok } from "@custos/contracts";
import { createRevocationGuard, type Connector } from "./connector.js";

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
  const guard = createRevocationGuard();

  return {
    tool: "mock-slack",
    dataCategories: ["messaging-content"],
    get messages() {
      return messages;
    },
    async call({ action, input, agentId }) {
      if (guard.isRevoked(agentId)) {
        return err({ code: "AGENT_REVOKED", agentId });
      }
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
    async revoke(agentId) {
      guard.revoke(agentId);
    },
  };
}

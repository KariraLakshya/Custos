import { describe, expect, it } from "vitest";
import { AGENT_NAME_MAX_LENGTH, agentNameSchema } from "./agent-name.js";

describe("agentNameSchema", () => {
  it.each(["billing-bot", "a", "Agent 7", "v1.2_test", "x".repeat(AGENT_NAME_MAX_LENGTH)])(
    "accepts %j",
    (name) => {
      expect(agentNameSchema.safeParse(name).success).toBe(true);
    },
  );

  it.each([
    ["empty", ""],
    ["too long", "x".repeat(AGENT_NAME_MAX_LENGTH + 1)],
    ["leading space", " bot"],
    ["leading dot", ".bot"],
    ["leading dash", "-bot"],
    ["newline", "bot\nRefused: fake"],
    ["terminal escape", "bot\u001b[31m"],
    ["non-ASCII", "bøt"],
    ["markup", "<b>bot</b>"],
  ])("refuses %s", (_label, name) => {
    expect(agentNameSchema.safeParse(name).success).toBe(false);
  });

  it.each([42, null, ["bot"], { name: "bot" }])("refuses the non-string %j", (value) => {
    expect(agentNameSchema.safeParse(value).success).toBe(false);
  });
});

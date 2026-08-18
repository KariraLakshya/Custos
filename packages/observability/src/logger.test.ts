import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { createLogger } from "./logger.js";

function captureStream() {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, callback) {
      chunks.push(chunk.toString());
      callback();
    },
  });
  return { stream, lines: () => chunks.map((c) => JSON.parse(c)) };
}

describe("createLogger", () => {
  it("redacts secret fields even if the caller tries to disable redaction", () => {
    const { stream, lines } = captureStream();
    const logger = createLogger({ redact: { paths: [], censor: "leaked" } }, stream);
    logger.info({ token: "shh", nested: { apiKey: "shh2" } }, "test");
    const [entry] = lines();
    expect(entry.token).toBe("[REDACTED]");
    expect(entry.nested.apiKey).toBe("[REDACTED]");
  });

  it("builds a working logger when no destination stream is given", () => {
    const logger = createLogger({ level: "silent" });
    expect(logger).toBeDefined();
  });

  it("logs non-secret fields unchanged", () => {
    const { stream, lines } = captureStream();
    const logger = createLogger({}, stream);
    logger.info({ agentId: "abc123" }, "test");
    const [entry] = lines();
    expect(entry.agentId).toBe("abc123");
    expect(entry.msg).toBe("test");
  });
});

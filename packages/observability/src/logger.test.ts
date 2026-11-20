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

  it("redacts an authorization header, which carries control-plane API keys", () => {
    const { stream, lines } = captureStream();
    const logger = createLogger({}, stream);
    logger.info({ req: { headers: { authorization: "Bearer custos_operator_x_y" } } }, "test");
    const [entry] = lines();
    expect(entry.req.headers.authorization).toBe("[REDACTED]");
  });

  it("redacts an SSO login's operator key and a dashboard sign-in's one-time code (ADR 0022 §4)", () => {
    const { stream, lines } = captureStream();
    const logger = createLogger({}, stream);
    logger.info(
      {
        operatorKey: "custos_operator_x_y",
        body: { loginCode: "c".repeat(43) },
        res: { body: { operatorKey: "custos_operator_x_z" } },
        code: "INVALID_LOGIN_CODE",
      },
      "test",
    );
    const [entry] = lines();
    expect(entry.operatorKey).toBe("[REDACTED]");
    expect(entry.body.loginCode).toBe("[REDACTED]");
    expect(entry.res.body.operatorKey).toBe("[REDACTED]");
    // A refusal code is not a secret and stays readable.
    expect(entry.code).toBe("INVALID_LOGIN_CODE");
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

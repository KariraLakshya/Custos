import { describe, expect, it } from "vitest";
import { CustosError, ErrorCode } from "./errors.js";

describe("ErrorCode", () => {
  it("keeps the wire strings other services already depend on", () => {
    expect(ErrorCode.AGENT_REVOKED).toBe("AGENT_REVOKED");
    expect(ErrorCode.UNAVAILABLE).toBe("UNAVAILABLE");
    expect(ErrorCode.UNAUTHORIZED).toBe("UNAUTHORIZED");
  });
});

describe("CustosError", () => {
  it("carries a code and message", () => {
    const error = new CustosError(ErrorCode.INVALID_INPUT, "bad input");
    expect(error.code).toBe("INVALID_INPUT");
    expect(error.message).toBe("bad input");
    expect(error).toBeInstanceOf(Error);
  });

  it("preserves the cause chain", () => {
    const cause = new Error("root cause");
    const error = new CustosError(ErrorCode.UNKNOWN, "wrapped", { cause });
    expect(error.cause).toBe(cause);
  });
});

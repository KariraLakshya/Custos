import { describe, expect, it } from "vitest";
import { CustosError, ErrorCode } from "./errors.js";

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

import { describe, expect, it } from "vitest";
import { SDK_VERSION } from "./index.js";

describe("@custos/sdk", () => {
  it("exposes a version", () => {
    expect(typeof SDK_VERSION).toBe("string");
  });
});

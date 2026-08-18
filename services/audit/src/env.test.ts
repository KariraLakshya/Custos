import { describe, expect, it } from "vitest";
import { loadAuditEnv } from "./env.js";

describe("audit env", () => {
  it("defaults PORT to 4004", () => {
    expect(loadAuditEnv({}).PORT).toBe(4004);
  });

  it("coerces PORT from a string", () => {
    expect(loadAuditEnv({ PORT: "5000" }).PORT).toBe(5000);
  });
});

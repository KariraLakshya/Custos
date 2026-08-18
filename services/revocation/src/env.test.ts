import { describe, expect, it } from "vitest";
import { loadRevocationEnv } from "./env.js";

describe("revocation env", () => {
  it("defaults PORT to 4003", () => {
    expect(loadRevocationEnv({}).PORT).toBe(4003);
  });

  it("coerces PORT from a string", () => {
    expect(loadRevocationEnv({ PORT: "5000" }).PORT).toBe(5000);
  });
});

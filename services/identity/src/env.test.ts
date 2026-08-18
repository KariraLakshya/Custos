import { describe, expect, it } from "vitest";
import { loadIdentityEnv } from "./env.js";

describe("identity env", () => {
  it("defaults PORT to 4001", () => {
    expect(loadIdentityEnv({}).PORT).toBe(4001);
  });

  it("coerces PORT from a string", () => {
    expect(loadIdentityEnv({ PORT: "5000" }).PORT).toBe(5000);
  });
});

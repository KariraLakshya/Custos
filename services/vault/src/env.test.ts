import { describe, expect, it } from "vitest";
import { loadVaultEnv } from "./env.js";

describe("vault env", () => {
  it("defaults PORT to 4002", () => {
    expect(loadVaultEnv({}).PORT).toBe(4002);
  });

  it("coerces PORT from a string", () => {
    expect(loadVaultEnv({ PORT: "5000" }).PORT).toBe(5000);
  });
});

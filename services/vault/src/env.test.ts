import { describe, expect, it } from "vitest";
import { loadVaultEnv } from "./env.js";

const validMasterKey = "0".repeat(64);

describe("vault env", () => {
  it("defaults PORT to 4002", () => {
    expect(loadVaultEnv({ VAULT_MASTER_KEY: validMasterKey }).PORT).toBe(4002);
  });

  it("coerces PORT from a string", () => {
    expect(loadVaultEnv({ PORT: "5000", VAULT_MASTER_KEY: validMasterKey }).PORT).toBe(5000);
  });

  it("refuses to boot without VAULT_MASTER_KEY", () => {
    expect(() => loadVaultEnv({})).toThrow();
  });

  it("refuses to boot with a VAULT_MASTER_KEY that isn't 32 bytes of hex", () => {
    expect(() => loadVaultEnv({ VAULT_MASTER_KEY: "not-hex" })).toThrow();
  });
});

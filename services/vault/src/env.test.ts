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

  it("defaults the trusted issuer to the local identity service's DID", () => {
    expect(loadVaultEnv({ VAULT_MASTER_KEY: validMasterKey }).VAULT_TRUSTED_ISSUER_DID).toBe(
      "did:web:localhost%3A4001",
    );
  });

  it("accepts a configured trusted issuer DID", () => {
    expect(
      loadVaultEnv({
        VAULT_MASTER_KEY: validMasterKey,
        VAULT_TRUSTED_ISSUER_DID: "did:web:identity.custos.example",
      }).VAULT_TRUSTED_ISSUER_DID,
    ).toBe("did:web:identity.custos.example");
  });

  it("defaults the public URL and token-proof skew window", () => {
    const env = loadVaultEnv({ VAULT_MASTER_KEY: validMasterKey });
    expect(env.VAULT_PUBLIC_URL).toBe("http://localhost:4002");
    expect(env.VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS).toBe(60);
  });

  it("refuses a public URL that isn't a URL", () => {
    expect(() =>
      loadVaultEnv({ VAULT_MASTER_KEY: validMasterKey, VAULT_PUBLIC_URL: "vault" }),
    ).toThrow(/VAULT_PUBLIC_URL/);
  });

  it("refuses to boot without VAULT_MASTER_KEY", () => {
    expect(() => loadVaultEnv({})).toThrow();
  });

  it("refuses to boot with a VAULT_MASTER_KEY that isn't 32 bytes of hex", () => {
    expect(() => loadVaultEnv({ VAULT_MASTER_KEY: "not-hex" })).toThrow();
  });
});

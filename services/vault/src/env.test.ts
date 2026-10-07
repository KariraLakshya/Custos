import { describe, expect, it } from "vitest";
import { loadVaultEnv } from "./env.js";

const SERVICE_KEY = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

const validMasterKey = "0".repeat(64);

describe("vault env", () => {
  it("defaults PORT to 4002", () => {
    expect(
      loadVaultEnv({ VAULT_MASTER_KEY: validMasterKey, VAULT_SERVICE_KEY: SERVICE_KEY }).PORT,
    ).toBe(4002);
  });

  it("coerces PORT from a string", () => {
    expect(
      loadVaultEnv({
        PORT: "5000",
        VAULT_MASTER_KEY: validMasterKey,
        VAULT_SERVICE_KEY: SERVICE_KEY,
      }).PORT,
    ).toBe(5000);
  });

  it("defaults the trusted issuer to the local identity service's DID", () => {
    expect(
      loadVaultEnv({ VAULT_MASTER_KEY: validMasterKey, VAULT_SERVICE_KEY: SERVICE_KEY })
        .VAULT_TRUSTED_ISSUER_DID,
    ).toBe("did:web:localhost%3A4001");
  });

  it("accepts a configured trusted issuer DID", () => {
    expect(
      loadVaultEnv({
        VAULT_MASTER_KEY: validMasterKey,
        VAULT_SERVICE_KEY: SERVICE_KEY,
        VAULT_TRUSTED_ISSUER_DID: "did:web:identity.custos.example",
      }).VAULT_TRUSTED_ISSUER_DID,
    ).toBe("did:web:identity.custos.example");
  });

  it("defaults the public URL and token-proof skew window", () => {
    const env = loadVaultEnv({ VAULT_MASTER_KEY: validMasterKey, VAULT_SERVICE_KEY: SERVICE_KEY });
    expect(env.VAULT_PUBLIC_URL).toBe("http://localhost:4002");
    expect(env.VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS).toBe(60);
  });

  it("refuses a public URL that isn't a URL", () => {
    expect(() =>
      loadVaultEnv({
        VAULT_MASTER_KEY: validMasterKey,
        VAULT_SERVICE_KEY: SERVICE_KEY,
        VAULT_PUBLIC_URL: "vault",
      }),
    ).toThrow(/VAULT_PUBLIC_URL/);
  });

  it("refuses to boot without VAULT_MASTER_KEY", () => {
    expect(() => loadVaultEnv({})).toThrow();
  });

  it("refuses to boot with a VAULT_MASTER_KEY that isn't 32 bytes of hex", () => {
    expect(() => loadVaultEnv({ VAULT_MASTER_KEY: "not-hex" })).toThrow();
  });
});

describe("vault env service key (ADR 0008)", () => {
  const masterKey = "ab".repeat(32);

  it("is required, with no default", () => {
    expect(() => loadVaultEnv({ VAULT_MASTER_KEY: masterKey })).toThrow(/VAULT_SERVICE_KEY/);
  });

  it("must be a service key, not an operator key or anything else", () => {
    const operator = SERVICE_KEY.replace("custos_service_", "custos_operator_");
    for (const value of [operator, "not-a-key"]) {
      expect(() => loadVaultEnv({ VAULT_MASTER_KEY: masterKey, VAULT_SERVICE_KEY: value })).toThrow(
        /VAULT_SERVICE_KEY/,
      );
    }
  });
});

describe("vault env: client certificate instead of a service key (ADR 0009)", () => {
  const base = { VAULT_MASTER_KEY: "ab".repeat(32) };
  const mtls = { VAULT_MTLS_CERT: "vault.crt", VAULT_MTLS_KEY: "vault.key", MTLS_CA: "ca.crt" };
  const key = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

  it("accepts a client certificate with no service key", () => {
    const env = loadVaultEnv({ ...base, ...mtls });
    expect(env.VAULT_SERVICE_KEY).toBeUndefined();
    expect(env.VAULT_MTLS_CERT).toBe("vault.crt");
  });

  it("refuses both a service key and a client certificate", () => {
    expect(() => loadVaultEnv({ ...base, ...mtls, VAULT_SERVICE_KEY: key })).toThrow(/not both/);
  });

  it("refuses neither, naming both options", () => {
    expect(() => loadVaultEnv(base)).toThrow(/VAULT_MTLS_CERT/);
  });
});

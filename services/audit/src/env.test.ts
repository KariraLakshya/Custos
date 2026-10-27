import { describe, expect, it } from "vitest";
import { loadAuditEnv } from "./env.js";

const SEED = { AUDIT_SIGNING_SEED: "ab".repeat(32) };

describe("audit env", () => {
  it("defaults PORT to 4004", () => {
    expect(loadAuditEnv(SEED).PORT).toBe(4004);
  });

  it("coerces PORT from a string", () => {
    expect(loadAuditEnv({ ...SEED, PORT: "5000" }).PORT).toBe(5000);
  });

  it("defaults DATABASE_URL to the local compose Postgres", () => {
    expect(loadAuditEnv(SEED).DATABASE_URL).toBe("postgres://custos:custos@localhost:5433/custos");
  });

  it("defaults AUDIT_DID_DOMAIN to localhost:4004", () => {
    expect(loadAuditEnv(SEED).AUDIT_DID_DOMAIN).toBe("localhost:4004");
  });
});

describe("audit env: optional Envoy-only TLS listener (ADR 0009)", () => {
  it("is off by default", () => {
    expect(loadAuditEnv(SEED).AUDIT_MTLS_PORT).toBeUndefined();
  });

  it("reads the listener settings", () => {
    const env = loadAuditEnv({
      ...SEED,
      AUDIT_MTLS_PORT: "4014",
      AUDIT_MTLS_SERVER_CERT: "audit-server.crt",
      AUDIT_MTLS_SERVER_KEY: "audit-server.key",
      MTLS_CA: "ca.crt",
    });
    expect(env.AUDIT_MTLS_PORT).toBe(4014);
  });

  it("refuses a non-numeric port", () => {
    expect(() => loadAuditEnv({ ...SEED, AUDIT_MTLS_PORT: "tls" })).toThrow(/AUDIT_MTLS_PORT/);
  });
});

describe("audit env: signing key and sealing (ADR 0017)", () => {
  it("requires the seed for the default local provider, with no default", () => {
    expect(() => loadAuditEnv({})).toThrow(/AUDIT_SIGNING_SEED/);
  });

  it.each([
    ["too short", "ab".repeat(31)],
    ["not hex", "zz".repeat(32)],
  ])("refuses a seed that is %s", (_name, seed) => {
    expect(() => loadAuditEnv({ AUDIT_SIGNING_SEED: seed })).toThrow(/AUDIT_SIGNING_SEED/);
  });

  it("accepts kms with a key id and no seed, and refuses kms without one", () => {
    const env = loadAuditEnv({
      AUDIT_KEY_PROVIDER: "kms",
      AUDIT_SIGNING_KMS_KEY_ID: "alias/custos-audit",
    });
    expect(env.AUDIT_SIGNING_KMS_KEY_ID).toBe("alias/custos-audit");
    expect(() => loadAuditEnv({ ...SEED, AUDIT_KEY_PROVIDER: "kms" })).toThrow(
      /AUDIT_SIGNING_KMS_KEY_ID/,
    );
  });

  it("seals every 10 seconds by default, and refuses a non-positive interval", () => {
    expect(loadAuditEnv(SEED).AUDIT_SEAL_INTERVAL_MS).toBe(10_000);
    expect(() => loadAuditEnv({ ...SEED, AUDIT_SEAL_INTERVAL_MS: "0" })).toThrow(
      /AUDIT_SEAL_INTERVAL_MS/,
    );
  });
});

describe("audit env: seal store (ADR 0017 part 2a)", () => {
  it("is off by default", () => {
    expect(loadAuditEnv(SEED).AUDIT_SEAL_STORE_URL).toBeUndefined();
  });

  it("reads a Postgres URL, and refuses one that is not a URL", () => {
    const url = "postgres://custos_sealer:secret@localhost:5434/custos_seals";
    expect(loadAuditEnv({ ...SEED, AUDIT_SEAL_STORE_URL: url }).AUDIT_SEAL_STORE_URL).toBe(url);
    expect(() => loadAuditEnv({ ...SEED, AUDIT_SEAL_STORE_URL: "not a url" })).toThrow(
      /AUDIT_SEAL_STORE_URL/,
    );
  });
});

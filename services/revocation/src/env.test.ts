import { describe, expect, it } from "vitest";
import { loadRevocationEnv } from "./env.js";

const SERVICE_KEY = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

describe("revocation env", () => {
  it("defaults PORT to 4003", () => {
    expect(loadRevocationEnv({ REVOCATION_SERVICE_KEY: SERVICE_KEY }).PORT).toBe(4003);
  });

  it("coerces PORT from a string", () => {
    expect(loadRevocationEnv({ PORT: "5000", REVOCATION_SERVICE_KEY: SERVICE_KEY }).PORT).toBe(
      5000,
    );
  });
});

describe("revocation env service key (ADR 0008)", () => {
  it("is required, with no default", () => {
    expect(() => loadRevocationEnv({})).toThrow(/REVOCATION_SERVICE_KEY/);
  });

  it("must be a service key", () => {
    const operator = SERVICE_KEY.replace("custos_service_", "custos_operator_");
    expect(() => loadRevocationEnv({ REVOCATION_SERVICE_KEY: operator })).toThrow(
      /REVOCATION_SERVICE_KEY/,
    );
  });
});

describe("revocation env: client certificate instead of a service key (ADR 0009)", () => {
  const base = {};
  const mtls = {
    REVOCATION_MTLS_CERT: "revocation.crt",
    REVOCATION_MTLS_KEY: "revocation.key",
    MTLS_CA: "ca.crt",
  };
  const key = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

  it("accepts a client certificate with no service key", () => {
    const env = loadRevocationEnv({ ...base, ...mtls });
    expect(env.REVOCATION_SERVICE_KEY).toBeUndefined();
    expect(env.REVOCATION_MTLS_CERT).toBe("revocation.crt");
  });

  it("refuses both a service key and a client certificate", () => {
    expect(() => loadRevocationEnv({ ...base, ...mtls, REVOCATION_SERVICE_KEY: key })).toThrow(
      /not both/,
    );
  });

  it("refuses neither, naming both options", () => {
    expect(() => loadRevocationEnv(base)).toThrow(/REVOCATION_MTLS_CERT/);
  });
});

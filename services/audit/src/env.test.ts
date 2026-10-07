import { describe, expect, it } from "vitest";
import { loadAuditEnv } from "./env.js";

describe("audit env", () => {
  it("defaults PORT to 4004", () => {
    expect(loadAuditEnv({}).PORT).toBe(4004);
  });

  it("coerces PORT from a string", () => {
    expect(loadAuditEnv({ PORT: "5000" }).PORT).toBe(5000);
  });

  it("defaults DATABASE_URL to the local compose Postgres", () => {
    expect(loadAuditEnv({}).DATABASE_URL).toBe("postgres://custos:custos@localhost:5433/custos");
  });

  it("defaults AUDIT_DID_DOMAIN to localhost:4004", () => {
    expect(loadAuditEnv({}).AUDIT_DID_DOMAIN).toBe("localhost:4004");
  });
});

describe("audit env: optional Envoy-only TLS listener (ADR 0009)", () => {
  it("is off by default", () => {
    expect(loadAuditEnv({}).AUDIT_MTLS_PORT).toBeUndefined();
  });

  it("reads the listener settings", () => {
    const env = loadAuditEnv({
      AUDIT_MTLS_PORT: "4014",
      AUDIT_MTLS_SERVER_CERT: "audit-server.crt",
      AUDIT_MTLS_SERVER_KEY: "audit-server.key",
      MTLS_CA: "ca.crt",
    });
    expect(env.AUDIT_MTLS_PORT).toBe(4014);
  });

  it("refuses a non-numeric port", () => {
    expect(() => loadAuditEnv({ AUDIT_MTLS_PORT: "tls" })).toThrow(/AUDIT_MTLS_PORT/);
  });
});

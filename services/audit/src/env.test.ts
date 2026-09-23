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

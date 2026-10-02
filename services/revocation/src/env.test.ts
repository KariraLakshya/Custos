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

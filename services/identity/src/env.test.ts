import { describe, expect, it } from "vitest";
import { loadIdentityEnv } from "./env.js";

describe("identity env", () => {
  it("defaults PORT to 4001", () => {
    expect(loadIdentityEnv({}).PORT).toBe(4001);
  });

  it("coerces PORT from a string", () => {
    expect(loadIdentityEnv({ PORT: "5000" }).PORT).toBe(5000);
  });

  it("defaults IDENTITY_DID_DOMAIN to localhost:4001", () => {
    expect(loadIdentityEnv({}).IDENTITY_DID_DOMAIN).toBe("localhost:4001");
  });

  it("accepts a configured IDENTITY_DID_DOMAIN", () => {
    expect(
      loadIdentityEnv({ IDENTITY_DID_DOMAIN: "identity.custos.example" }).IDENTITY_DID_DOMAIN,
    ).toBe("identity.custos.example");
  });

  it("defaults DATABASE_URL to the local docker-compose Postgres", () => {
    expect(loadIdentityEnv({}).DATABASE_URL).toBe("postgres://custos:custos@localhost:5433/custos");
  });

  it("accepts a configured DATABASE_URL", () => {
    expect(loadIdentityEnv({ DATABASE_URL: "postgres://other/db" }).DATABASE_URL).toBe(
      "postgres://other/db",
    );
  });
});

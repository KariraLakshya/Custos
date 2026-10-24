import { describe, expect, it } from "vitest";
import { loadRevocationEnv } from "./env.js";

const SEED = { REVOCATION_SIGNING_SEED: "ab".repeat(32) };
const SERVICE_KEY = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

describe("revocation env", () => {
  it("defaults PORT to 4003", () => {
    expect(loadRevocationEnv({ ...SEED, REVOCATION_SERVICE_KEY: SERVICE_KEY }).PORT).toBe(4003);
  });

  it("coerces PORT from a string", () => {
    expect(
      loadRevocationEnv({ ...SEED, PORT: "5000", REVOCATION_SERVICE_KEY: SERVICE_KEY }).PORT,
    ).toBe(5000);
  });
});

describe("revocation env service key (ADR 0008)", () => {
  it("is required, with no default", () => {
    expect(() => loadRevocationEnv({ ...SEED })).toThrow(/REVOCATION_SERVICE_KEY/);
  });

  it("must be a service key", () => {
    const operator = SERVICE_KEY.replace("custos_service_", "custos_operator_");
    expect(() => loadRevocationEnv({ ...SEED, REVOCATION_SERVICE_KEY: operator })).toThrow(
      /REVOCATION_SERVICE_KEY/,
    );
  });
});

describe("revocation env: client certificate instead of a service key (ADR 0009)", () => {
  const base = { ...SEED };
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

describe("revocation env signing seed (ADR 0012)", () => {
  const withKey = { REVOCATION_SERVICE_KEY: SERVICE_KEY };

  it("is required, with no default", () => {
    expect(() => loadRevocationEnv(withKey)).toThrow(/REVOCATION_SIGNING_SEED/);
  });

  it.each([
    ["too short", "ab".repeat(31)],
    ["too long", "ab".repeat(33)],
    ["not hex", "zz".repeat(32)],
    ["empty", ""],
  ])("refuses a seed that is %s", (_name, seed) => {
    expect(() => loadRevocationEnv({ ...withKey, REVOCATION_SIGNING_SEED: seed })).toThrow(
      /REVOCATION_SIGNING_SEED/,
    );
  });
});

describe("revocation env: KMS signing key (ADR 0016)", () => {
  const withKey = { REVOCATION_SERVICE_KEY: SERVICE_KEY };

  it("defaults to the local provider", () => {
    expect(loadRevocationEnv({ ...withKey, ...SEED }).REVOCATION_KEY_PROVIDER).toBe("local");
  });

  it("accepts kms with a key id and no seed", () => {
    const env = loadRevocationEnv({
      ...withKey,
      REVOCATION_KEY_PROVIDER: "kms",
      REVOCATION_SIGNING_KMS_KEY_ID: "alias/custos-revocation",
    });
    expect(env.REVOCATION_SIGNING_KMS_KEY_ID).toBe("alias/custos-revocation");
    expect(env.REVOCATION_SIGNING_SEED).toBeUndefined();
  });

  it("refuses kms without a key id", () => {
    expect(() =>
      loadRevocationEnv({ ...withKey, ...SEED, REVOCATION_KEY_PROVIDER: "kms" }),
    ).toThrow(/REVOCATION_SIGNING_KMS_KEY_ID/);
  });

  it("refuses an unknown provider", () => {
    expect(() =>
      loadRevocationEnv({ ...withKey, ...SEED, REVOCATION_KEY_PROVIDER: "file" }),
    ).toThrow(/REVOCATION_KEY_PROVIDER/);
  });
});

describe("revocation env: status list reuse (ADR 0016)", () => {
  const base = { ...SEED, REVOCATION_SERVICE_KEY: SERVICE_KEY };

  it("defaults to 5 seconds", () => {
    expect(loadRevocationEnv(base).REVOCATION_STATUS_REUSE_MS).toBe(5_000);
  });

  it.each(["0", "-1", "1.5", "soon"])("refuses %s", (value) => {
    expect(() => loadRevocationEnv({ ...base, REVOCATION_STATUS_REUSE_MS: value })).toThrow(
      /REVOCATION_STATUS_REUSE_MS/,
    );
  });
});

describe("revocation env: published status list (ADR 0014)", () => {
  const base = { ...SEED, REVOCATION_SERVICE_KEY: SERVICE_KEY };
  const list = { REVOCATION_PUBLISHED_LIST_URL: "https://lists.example/a/status/revocation" };

  it("is off when no URL is set, and needs none of the other settings", () => {
    const env = loadRevocationEnv(base);
    expect(env.REVOCATION_PUBLISHED_LIST_URL).toBeUndefined();
    expect(env.REVOCATION_PUBLISHED_MAX_AGE_SECONDS).toBeUndefined();
  });

  it("requires the window and the poll interval when a URL is set: they have no defaults", () => {
    expect(() => loadRevocationEnv({ ...base, ...list })).toThrow(
      /REVOCATION_PUBLISHED_MAX_AGE_SECONDS/,
    );
    expect(() =>
      loadRevocationEnv({ ...base, ...list, REVOCATION_PUBLISHED_MAX_AGE_SECONDS: "3600" }),
    ).toThrow(/REVOCATION_PUBLISHED_POLL_SECONDS/);
  });

  it("accepts a complete configuration, with a 5 s clock allowance by default", () => {
    const env = loadRevocationEnv({
      ...base,
      ...list,
      REVOCATION_PUBLISHED_MAX_AGE_SECONDS: "3600",
      REVOCATION_PUBLISHED_POLL_SECONDS: "20",
    });
    expect(env.REVOCATION_PUBLISHED_MAX_AGE_SECONDS).toBe(3600);
    expect(env.REVOCATION_PUBLISHED_POLL_SECONDS).toBe(20);
    expect(env.REVOCATION_PUBLISHED_MAX_CLOCK_SKEW_SECONDS).toBe(5);
  });

  it("refuses a URL that is not a URL, and a window that is zero, negative or fractional", () => {
    const complete = { ...base, ...list, REVOCATION_PUBLISHED_POLL_SECONDS: "20" };
    expect(() =>
      loadRevocationEnv({
        ...complete,
        REVOCATION_PUBLISHED_LIST_URL: "not a url",
        REVOCATION_PUBLISHED_MAX_AGE_SECONDS: "60",
      }),
    ).toThrow(/REVOCATION_PUBLISHED_LIST_URL/);
    for (const bad of ["0", "-5", "1.5", "soon"]) {
      expect(() =>
        loadRevocationEnv({ ...complete, REVOCATION_PUBLISHED_MAX_AGE_SECONDS: bad }),
      ).toThrow(/REVOCATION_PUBLISHED_MAX_AGE_SECONDS/);
    }
  });

  it("refuses a poll interval that is not shorter than the window", () => {
    const complete = { ...base, ...list, REVOCATION_PUBLISHED_MAX_AGE_SECONDS: "60" };
    for (const poll of ["60", "61", "3600"]) {
      expect(() =>
        loadRevocationEnv({ ...complete, REVOCATION_PUBLISHED_POLL_SECONDS: poll }),
      ).toThrow(/REVOCATION_PUBLISHED_POLL_SECONDS/);
    }
    expect(
      loadRevocationEnv({ ...complete, REVOCATION_PUBLISHED_POLL_SECONDS: "59" })
        .REVOCATION_PUBLISHED_POLL_SECONDS,
    ).toBe(59);
  });
});

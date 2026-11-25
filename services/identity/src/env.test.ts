import { describe, expect, it } from "vitest";
import { loadIdentityEnv } from "./env.js";

// The issuer seed is required; every other test supplies one so it can test its own variable.
const SERVICE_KEY = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");
const SEED = { IDENTITY_ISSUER_SEED: "ab".repeat(32), IDENTITY_SERVICE_KEY: SERVICE_KEY };

describe("identity env", () => {
  it("refuses to load without an issuer seed — no default key, ephemeral or known", () => {
    expect(() => loadIdentityEnv({ IDENTITY_SERVICE_KEY: SERVICE_KEY })).toThrow(
      /IDENTITY_ISSUER_SEED/,
    );
  });

  it.each([
    ["too short", "ab".repeat(31)],
    ["too long", "ab".repeat(33)],
    ["not hex", "zz".repeat(32)],
  ])("refuses an issuer seed that is %s", (_label, seed) => {
    expect(() => loadIdentityEnv({ IDENTITY_ISSUER_SEED: seed })).toThrow(/IDENTITY_ISSUER_SEED/);
  });

  describe("service key (ADR 0008)", () => {
    it("is required, with no default", () => {
      expect(() => loadIdentityEnv({ IDENTITY_ISSUER_SEED: "ab".repeat(32) })).toThrow(
        /IDENTITY_SERVICE_KEY/,
      );
    });

    it("must be a service key, not an operator key or anything else", () => {
      const operator = SERVICE_KEY.replace("custos_service_", "custos_operator_");
      for (const value of [operator, "not-a-key", ""]) {
        expect(() => loadIdentityEnv({ ...SEED, IDENTITY_SERVICE_KEY: value })).toThrow(
          /IDENTITY_SERVICE_KEY/,
        );
      }
    });

    it("never echoes the key in the validation error", () => {
      const operator = SERVICE_KEY.replace("custos_service_", "custos_operator_");
      expect(() => loadIdentityEnv({ ...SEED, IDENTITY_SERVICE_KEY: operator })).toThrow(
        expect.objectContaining({ message: expect.not.stringContaining("k".repeat(43)) }),
      );
    });
  });

  describe("issuer key provider", () => {
    it("defaults to the local provider", () => {
      expect(loadIdentityEnv(SEED).IDENTITY_KEY_PROVIDER).toBe("local");
    });

    it("uses KMS with a key id and no seed", () => {
      const env = loadIdentityEnv({
        IDENTITY_SERVICE_KEY: SERVICE_KEY,
        IDENTITY_KEY_PROVIDER: "kms",
        IDENTITY_ISSUER_KMS_KEY_ID: "arn:aws:kms:ap-southeast-1:111122223333:key/abc",
      });
      expect(env.IDENTITY_KEY_PROVIDER).toBe("kms");
      expect(env.IDENTITY_ISSUER_KMS_KEY_ID).toBe(
        "arn:aws:kms:ap-southeast-1:111122223333:key/abc",
      );
    });

    it("refuses KMS without a key id — no silent fallback to a local key", () => {
      expect(() =>
        loadIdentityEnv({ IDENTITY_SERVICE_KEY: SERVICE_KEY, IDENTITY_KEY_PROVIDER: "kms" }),
      ).toThrow(/IDENTITY_ISSUER_KMS_KEY_ID/);
    });

    it("refuses an unknown provider", () => {
      expect(() => loadIdentityEnv({ ...SEED, IDENTITY_KEY_PROVIDER: "vault" })).toThrow(
        /IDENTITY_KEY_PROVIDER/,
      );
    });

    it("still validates a seed's format even when KMS is selected", () => {
      expect(() =>
        loadIdentityEnv({
          IDENTITY_KEY_PROVIDER: "kms",
          IDENTITY_ISSUER_KMS_KEY_ID: "key-1",
          IDENTITY_ISSUER_SEED: "not-hex",
        }),
      ).toThrow(/IDENTITY_ISSUER_SEED/);
    });
  });

  it("accepts a 64-hex-character issuer seed", () => {
    expect(loadIdentityEnv(SEED).IDENTITY_ISSUER_SEED).toBe("ab".repeat(32));
  });

  it("defaults the registration proof skew window to 60 seconds", () => {
    expect(loadIdentityEnv(SEED).IDENTITY_REGISTRATION_PROOF_MAX_SKEW_SECONDS).toBe(60);
  });

  it("defaults PORT to 4001", () => {
    expect(loadIdentityEnv(SEED).PORT).toBe(4001);
  });

  it("coerces PORT from a string", () => {
    expect(loadIdentityEnv({ ...SEED, PORT: "5000" }).PORT).toBe(5000);
  });

  it("defaults IDENTITY_DID_DOMAIN to localhost:4001", () => {
    expect(loadIdentityEnv(SEED).IDENTITY_DID_DOMAIN).toBe("localhost:4001");
  });

  it("accepts a configured IDENTITY_DID_DOMAIN", () => {
    expect(
      loadIdentityEnv({ ...SEED, IDENTITY_DID_DOMAIN: "identity.custos.example" })
        .IDENTITY_DID_DOMAIN,
    ).toBe("identity.custos.example");
  });

  it("defaults DATABASE_URL to the local docker-compose Postgres", () => {
    expect(loadIdentityEnv(SEED).DATABASE_URL).toBe(
      "postgres://custos:custos@localhost:5433/custos",
    );
  });

  it("accepts a configured DATABASE_URL", () => {
    expect(loadIdentityEnv({ ...SEED, DATABASE_URL: "postgres://other/db" }).DATABASE_URL).toBe(
      "postgres://other/db",
    );
  });
});

describe("identity env: client certificate instead of a service key (ADR 0009)", () => {
  const base = { IDENTITY_ISSUER_SEED: "ab".repeat(32) };
  const mtls = {
    IDENTITY_MTLS_CERT: "identity.crt",
    IDENTITY_MTLS_KEY: "identity.key",
    MTLS_CA: "ca.crt",
  };
  const key = ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_");

  it("accepts a client certificate with no service key", () => {
    const env = loadIdentityEnv({ ...base, ...mtls });
    expect(env.IDENTITY_SERVICE_KEY).toBeUndefined();
    expect(env.IDENTITY_MTLS_CERT).toBe("identity.crt");
  });

  it("refuses both a service key and a client certificate", () => {
    expect(() => loadIdentityEnv({ ...base, ...mtls, IDENTITY_SERVICE_KEY: key })).toThrow(
      /not both/,
    );
  });

  it("refuses neither, naming both options", () => {
    expect(() => loadIdentityEnv(base)).toThrow(/IDENTITY_MTLS_CERT/);
  });
});

describe("identity env: operator SSO (ADR 0010)", () => {
  const base = { IDENTITY_ISSUER_SEED: "ab".repeat(32), IDENTITY_SERVICE_KEY: SERVICE_KEY };
  const sso = {
    SSO_ISSUER: "https://login.acme.test/realms/custos",
    SSO_CLIENT_ID: "custos-identity",
    SSO_CLIENT_SECRET: "s",
    SSO_REDIRECT_URL: "https://custos.acme.test/operator/callback",
    SSO_GROUP_SCOPES: '{"custos-admins":["agents:register"]}',
  };

  it("is off when nothing is set, with an 8-hour session by default", () => {
    const env = loadIdentityEnv(base);
    expect(env.SSO_ISSUER).toBeUndefined();
    expect(env.SSO_SESSION_HOURS).toBe(8);
  });

  it("accepts a complete https configuration", () => {
    expect(loadIdentityEnv({ ...base, ...sso }).SSO_CLIENT_ID).toBe("custos-identity");
  });

  it("refuses a partial configuration", () => {
    expect(() => loadIdentityEnv({ ...base, SSO_ISSUER: sso.SSO_ISSUER })).toThrow(
      /SSO needs all of/,
    );
  });

  it("refuses a plain-http issuer unless it is local and explicitly allowed", () => {
    expect(() =>
      loadIdentityEnv({ ...base, ...sso, SSO_ISSUER: "http://login.acme.test/realms/custos" }),
    ).toThrow(/http:\/\/ issuer is allowed only for localhost/);
    expect(() =>
      loadIdentityEnv({ ...base, ...sso, SSO_ISSUER: "http://localhost:8180/realms/custos" }),
    ).toThrow(/SSO_ALLOW_HTTP_ISSUER=true/);
    expect(() =>
      loadIdentityEnv({
        ...base,
        ...sso,
        SSO_ISSUER: "http://login.acme.test/realms/custos",
        SSO_ALLOW_HTTP_ISSUER: "true",
      }),
    ).toThrow(/only for localhost/);
    expect(
      loadIdentityEnv({
        ...base,
        ...sso,
        SSO_ISSUER: "http://localhost:8180/realms/custos",
        SSO_ALLOW_HTTP_ISSUER: "true",
      }).SSO_ISSUER,
    ).toBe("http://localhost:8180/realms/custos");
  });

  it.each(["0", "25", "1.5"])("refuses a session of %s hours", (hours) => {
    expect(() => loadIdentityEnv({ ...base, SSO_SESSION_HOURS: hours })).toThrow(
      /SSO_SESSION_HOURS/,
    );
  });
});

describe("identity env: dashboard return addresses (ADR 0022 §4)", () => {
  const base = { IDENTITY_ISSUER_SEED: "ab".repeat(32), IDENTITY_SERVICE_KEY: SERVICE_KEY };
  const sso = {
    SSO_ISSUER: "https://login.acme.test/realms/custos",
    SSO_CLIENT_ID: "custos-identity",
    SSO_CLIENT_SECRET: "s",
    SSO_REDIRECT_URL: "https://custos.acme.test/operator/callback",
    SSO_GROUP_SCOPES: '{"custos-admins":["agents:read"]}',
  };

  it("accepts exact https addresses, and http ones for this computer only", () => {
    const urls = '["https://dash.acme.test/login/done","http://localhost:4005/login/done"]';
    expect(loadIdentityEnv({ ...base, ...sso, SSO_RETURN_URLS: urls }).SSO_RETURN_URLS).toBe(urls);
  });

  it.each([
    ["not JSON", "http://localhost:4005/login/done", /not valid JSON/],
    ["an empty list", "[]", /non-empty list/],
    ["not a list", '{"a":"http://localhost:4005/login/done"}', /non-empty list/],
    ["a non-string entry", "[4005]", /must list strings/],
    ["an empty entry", '[""]', /not an absolute URL/],
    ["a relative address", '["/login/done"]', /not an absolute URL/],
    ["a missing path slash", '["http://localhost:4005"]', /write .* as .*4005\//],
    ["upper-case scheme and host", '["HTTP://LOCALHOST:4005/login/done"]', /write/],
    ["a percent-encodable character", '["http://localhost:4005/login/dône"]', /write/],
    ["a query", '["http://localhost:4005/login/done?next=/"]', /no query, fragment/],
    ["an empty query", '["http://localhost:4005/login/done?"]', /no query, fragment/],
    ["a fragment", '["http://localhost:4005/login/done#x"]', /no query, fragment/],
    ["user info", '["https://user:pw@dash.acme.test/login/done"]', /user info/],
    ["plain http off this computer", '["http://dash.acme.test/login/done"]', /must be https/],
    ["another scheme", '["javascript:alert(1)"]', /must be https/],
  ])("refuses to boot on %s", (_label, value, message) => {
    expect(() => loadIdentityEnv({ ...base, ...sso, SSO_RETURN_URLS: value })).toThrow(message);
    expect(() => loadIdentityEnv({ ...base, ...sso, SSO_RETURN_URLS: value })).toThrow(
      /SSO_RETURN_URLS/,
    );
  });

  it("refuses to boot with return addresses but no SSO", () => {
    expect(() =>
      loadIdentityEnv({ ...base, SSO_RETURN_URLS: '["http://localhost:4005/login/done"]' }),
    ).toThrow(/SSO_RETURN_URLS needs SSO configured/);
  });

  it("refuses an empty value rather than reading it as unset", () => {
    expect(() => loadIdentityEnv({ ...base, ...sso, SSO_RETURN_URLS: "" })).toThrow(
      /SSO_RETURN_URLS/,
    );
  });
});

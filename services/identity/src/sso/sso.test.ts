import { randomUUID, type KeyObject } from "node:crypto";
import { Writable } from "node:stream";
import type { AuditEvent } from "@custos/audit-client";
import { createApiKeyAuthenticator, createApiKeyStore } from "@custos/control-plane-auth";
import { createLocalKeyProvider, err } from "@custos/core";
import { createLogger } from "@custos/observability";
import { createTestControlPlane } from "@custos/testing/control-plane";
import { startTestOidcProvider, type TestOidcProvider } from "@custos/testing/oidc-provider";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb } from "../db/client.js";
import { buildServer } from "../server.js";
import { loadIdentityEnv, type Env } from "../env.js";
import { createOperatorSsoFromEnv, discoverProvider } from "./boot.js";
import { parseGroupScopes, parseReturnUrls, readOnly, scopesForGroups } from "./config.js";
import { createOperatorSso, LOGIN_CODE_TTL_MS, type OperatorSso } from "./sso.js";
import { createLoginTransactions } from "./transactions.js";

/**
 * Operator SSO (ADR 0010) against a minimal OIDC provider run inside the
 * test (`@custos/testing/oidc-provider`). A real provider never issues the
 * broken tokens the build plan's DONE check needs (bad signature, wrong
 * issuer, audience or nonce, expired), so this one does. The happy path
 * against real Keycloak is in sso-keycloak.test.ts.
 */

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);
const keys = createApiKeyStore(db);
const CLIENT_ID = "custos-identity";
const REDIRECT = "http://127.0.0.1:5899/operator/callback";

let oidcProvider: TestOidcProvider;
let issuer: string;

beforeAll(async () => {
  oidcProvider = await startTestOidcProvider();
  issuer = oidcProvider.issuer;
});

afterAll(async () => {
  await oidcProvider.close();
  await db.$client.end();
});

async function ssoUnderTest(
  groupScopes = '{"custos-admins":["agents:register","agents:revoke"],"custos-auditors":[]}',
  reported: AuditEvent[] = [],
): Promise<OperatorSso> {
  // The same provider setup the service uses at boot.
  const config = await discoverProvider({
    issuer,
    clientId: CLIENT_ID,
    clientSecret: "test-secret",
    allowHttp: true,
  });
  const mapping = parseGroupScopes(groupScopes);
  if (!mapping.ok) throw new Error(mapping.error);
  return createOperatorSso({
    config,
    redirectUrl: REDIRECT,
    groupScopes: mapping.value,
    sessionMs: 8 * 3_600_000,
    keys,
    transactions: createLoginTransactions({ clock: { now: () => new Date() } }),
    clock: { now: () => new Date() },
    report: (event) => reported.push(event),
  });
}

/** Runs one login whose ID token `claims` builds, given the login's nonce. */
async function login(
  sso: OperatorSso,
  claims: (nonce: string, now: number) => object,
  key?: KeyObject,
) {
  const started = await sso.start();
  if (!started) throw new Error("login not started");
  const url = new URL(started.authorizationUrl);
  const state = url.searchParams.get("state") ?? "";
  const now = Math.floor(Date.now() / 1000);
  oidcProvider.respondWith(claims(url.searchParams.get("nonce") ?? "", now), key);
  const outcome = await sso.callback(`code=code-${randomUUID()}&state=${state}`);
  return { started, url, state, outcome };
}

const good =
  (overrides: object = {}) =>
  (nonce: string, now: number) => ({
    iss: issuer,
    aud: CLIENT_ID,
    sub: `user-${randomUUID()}`,
    email: `alice-${randomUUID()}@acme.test`,
    groups: ["custos-admins"],
    nonce,
    iat: now,
    exp: now + 300,
    ...overrides,
  });

describe("operator SSO (ADR 0010)", () => {
  it("sends the provider PKCE (S256), state and nonce, and the registered redirect", async () => {
    const started = await (await ssoUnderTest()).start();
    const url = new URL(started!.authorizationUrl);
    expect(url.origin + url.pathname).toBe(`${issuer}/authorize`);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.searchParams.get("state")).toBeTruthy();
    expect(url.searchParams.get("nonce")).toBeTruthy();
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT);
    expect(url.searchParams.get("scope")).toBe("openid email profile");
  });

  it("turns a valid login into a short-lived operator key named after the person, once", async () => {
    const reported: AuditEvent[] = [];
    const sso = await ssoUnderTest(undefined, reported);
    const before = Date.now();
    const { started, outcome } = await login(sso, good({ email: "alice@acme.test" }));
    expect(outcome.state).toBe("complete");
    if (outcome.state !== "complete") return;

    const authenticated = await createApiKeyAuthenticator({
      keys,
      clock: { now: () => new Date() },
    }).authenticate({ headers: { authorization: `Bearer ${outcome.login.operatorKey}` } });
    expect(authenticated.ok && authenticated.value).toMatchObject({
      kind: "operator",
      name: "alice@acme.test",
      scopes: new Set(["agents:register", "agents:revoke"]),
    });
    const row = await keys.findById(authenticated.ok ? authenticated.value.id : "");
    expect(row?.createdVia).toBe("sso");
    const lifetime = outcome.login.expiresAt.getTime() - before;
    expect(lifetime).toBeGreaterThan(8 * 3_600_000 - 60_000);
    expect(lifetime).toBeLessThanOrEqual(8 * 3_600_000 + 60_000);
    expect(reported).toEqual([
      expect.objectContaining({
        action: "operator.login",
        principal: expect.objectContaining({ kind: "operator", name: "alice@acme.test" }),
      }),
    ]);

    // The terminal gets the key exactly once.
    expect(sso.poll(started.loginId).state).toBe("complete");
    expect(sso.poll(started.loginId).state).toBe("unknown");
  });

  it("refuses to replay a completed login's redirect: state is single-use", async () => {
    const sso = await ssoUnderTest();
    const { state, outcome } = await login(sso, good());
    expect(outcome.state).toBe("complete");
    expect(await sso.callback(`code=again&state=${state}`)).toEqual({ state: "unknown" });
  });

  it("refuses a redirect with an unknown state", async () => {
    const sso = await ssoUnderTest();
    expect(await sso.callback("code=x&state=forged")).toEqual({ state: "unknown" });
    expect(await sso.callback("code=x")).toEqual({ state: "unknown" });
  });

  // The build plan's DONE check: each proven to fail, and no key created.
  it.each([
    ["a bad signature (signed by an unknown key)", good(), "impostor"],
    ["the wrong issuer", good({ iss: "http://evil.example" }), undefined],
    ["the wrong audience", good({ aud: "someone-else" }), undefined],
    ["the wrong nonce", (_nonce: string, now: number) => good()("not-the-nonce", now), undefined],
    [
      "an expired token",
      (nonce: string, now: number) => good({ iat: now - 7200, exp: now - 3600 })(nonce, now),
      undefined,
    ],
  ])("refuses an ID token with %s", async (_label, claims, key) => {
    const sso = await ssoUnderTest();
    const email = `rejected-${randomUUID()}@acme.test`;
    const { started, outcome } = await login(
      sso,
      (nonce, now) => ({ ...claims(nonce, now), email }),
      key === "impostor" ? oidcProvider.impostorKey : undefined,
    );
    expect(outcome).toEqual({ state: "failed", reason: "TOKEN_REJECTED" });
    expect(sso.poll(started.loginId)).toEqual({ state: "failed", reason: "TOKEN_REJECTED" });
    expect((await keys.list()).some((row) => row.name === email)).toBe(false);
  });

  it.each([
    ["no groups at all", undefined],
    ["only groups the mapping doesn't know", ["engineering"]],
    ["only a group mapped to no scopes", ["custos-auditors"]],
  ])("refuses a person with %s, creating no key", async (_label, groups) => {
    const sso = await ssoUnderTest();
    const email = `nogroup-${randomUUID()}@acme.test`;
    const { outcome } = await login(sso, good({ groups, email }));
    expect(outcome).toEqual({ state: "failed", reason: "NO_MAPPED_GROUP" });
    expect((await keys.list()).some((row) => row.name === email)).toBe(false);
  });

  it("uses the subject when the token has no email", async () => {
    const sso = await ssoUnderTest();
    const sub = `user-${randomUUID()}`;
    const { outcome } = await login(sso, (nonce, now) => {
      const claims: Record<string, unknown> = good({ sub })(nonce, now);
      delete claims.email;
      return claims;
    });
    expect(outcome.state === "complete" && outcome.login.name).toBe(sub);
  });
});

describe("operator SSO routes", () => {
  const controlPlane = createTestControlPlane(db);

  async function server(sso?: OperatorSso) {
    return buildServer({
      db,
      controlPlaneAuth: controlPlane.guard,
      didDomain: "identity.custos.example",
      issuerKey: {
        keyProvider: createLocalKeyProvider({
          importedKeys: { issuer: new Uint8Array(32).fill(7) },
        }),
        keyId: "issuer",
      },
      statusAllocator: {
        allocate: async () => err({ code: "STATUS_ALLOCATION_FAILED", reason: "unused" }),
      },
      auditReporter: { report: () => {} },
      ...(sso ? { operatorSso: () => sso } : {}),
    });
  }

  it("don't exist without SSO configured", async () => {
    const app = await server();
    expect((await app.inject({ method: "POST", url: "/operator/login" })).statusCode).toBe(404);
  });

  it("run a whole login: start, browser redirect back, then the terminal collects the key once", async () => {
    const app = await server(await ssoUnderTest());
    const started = await app.inject({ method: "POST", url: "/operator/login" });
    expect(started.statusCode).toBe(201);
    expect(started.headers["cache-control"]).toBe("no-store");
    const { loginId, authorizationUrl } = started.json() as {
      loginId: string;
      authorizationUrl: string;
    };
    expect(loginId).toMatch(/^[0-9a-f]{32}$/);

    const poll = () => app.inject({ method: "GET", url: `/operator/login/${loginId}` });
    expect((await poll()).statusCode).toBe(202);

    const url = new URL(authorizationUrl);
    const email = `route-${randomUUID()}@acme.test`;
    oidcProvider.respondWith(
      good({ email })(url.searchParams.get("nonce") ?? "", Math.floor(Date.now() / 1000)),
    );
    const back = await app.inject({
      method: "GET",
      url: `/operator/callback?code=c&state=${url.searchParams.get("state")}`,
    });
    expect(back.statusCode).toBe(200);
    expect(back.body).toContain(`Signed in to Custos as ${email}`);
    expect(back.body).not.toContain("custos_operator_");

    const collected = await poll();
    expect(collected.statusCode).toBe(200);
    expect(collected.headers["cache-control"]).toBe("no-store");
    expect(collected.json()).toMatchObject({
      operatorKey: expect.stringMatching(/^custos_operator_/),
      name: email,
    });
    expect((await poll()).statusCode).toBe(404);
  });

  it("report a refused login to the terminal without detail in the browser", async () => {
    const app = await server(await ssoUnderTest());
    const { loginId, authorizationUrl } = (
      await app.inject({ method: "POST", url: "/operator/login" })
    ).json() as { loginId: string; authorizationUrl: string };
    const url = new URL(authorizationUrl);
    oidcProvider.respondWith(
      good({ aud: "someone-else" })(
        url.searchParams.get("nonce") ?? "",
        Math.floor(Date.now() / 1000),
      ),
    );
    const back = await app.inject({
      method: "GET",
      url: `/operator/callback?code=c&state=${url.searchParams.get("state")}`,
    });
    expect(back.statusCode).toBe(401);
    expect(back.body).toBe("Custos sign-in failed. Return to your terminal for details.");
    const polled = await app.inject({ method: "GET", url: `/operator/login/${loginId}` });
    expect(polled.statusCode).toBe(401);
    expect(polled.json()).toEqual({ error: { code: "TOKEN_REJECTED" } });
  });

  it("refuse a redirect with an unknown state, and malformed or unknown login ids", async () => {
    const app = await server(await ssoUnderTest());
    expect(
      (await app.inject({ method: "GET", url: "/operator/callback?code=c&state=nope" })).statusCode,
    ).toBe(400);
    expect((await app.inject({ method: "GET", url: "/operator/callback" })).statusCode).toBe(400);
    expect((await app.inject({ method: "GET", url: "/operator/login/not-an-id" })).statusCode).toBe(
      400,
    );
    expect(
      (await app.inject({ method: "GET", url: `/operator/login/${"0".repeat(32)}` })).statusCode,
    ).toBe(404);
  });

  it("answer 503 when too many logins are in flight", async () => {
    const config = await discoverProvider({
      issuer,
      clientId: CLIENT_ID,
      clientSecret: "s",
      allowHttp: true,
    });
    const mapping = parseGroupScopes('{"custos-admins":["agents:register"]}');
    if (!mapping.ok) throw new Error(mapping.error);
    const sso = createOperatorSso({
      config,
      redirectUrl: REDIRECT,
      groupScopes: mapping.value,
      sessionMs: 3_600_000,
      keys,
      transactions: createLoginTransactions({ clock: { now: () => new Date() }, maxPending: 1 }),
      clock: { now: () => new Date() },
    });
    const app = await server(sso);
    expect((await app.inject({ method: "POST", url: "/operator/login" })).statusCode).toBe(201);
    const busy = await app.inject({ method: "POST", url: "/operator/login" });
    expect(busy.statusCode).toBe(503);
    expect(busy.json()).toEqual({ error: { code: "SSO_BUSY" } });
  });
});

describe("login transactions", () => {
  it("expire after their lifetime", () => {
    let now = 0;
    const tx = createLoginTransactions({ clock: { now: () => new Date(now) }, ttlMs: 1_000 });
    const pending = tx.start({ state: "s", nonce: "n", codeVerifier: "v" })!;
    now = 999;
    expect(tx.findByState("s")?.loginId).toBe(pending.loginId);
    now = 1_000;
    expect(tx.findByState("s")).toBeNull();
    expect(tx.take(pending.loginId)).toEqual({ state: "unknown" });
  });

  it("refuse new logins when full, rather than evicting someone else's", () => {
    const tx = createLoginTransactions({ clock: { now: () => new Date(0) }, maxPending: 2 });
    expect(tx.start({ state: "a", nonce: "n", codeVerifier: "v" })).not.toBeNull();
    expect(tx.start({ state: "b", nonce: "n", codeVerifier: "v" })).not.toBeNull();
    expect(tx.start({ state: "c", nonce: "n", codeVerifier: "v" })).toBeNull();
    expect(tx.findByState("a")).not.toBeNull();
  });

  it("keep a pending login pending when polled", () => {
    const tx = createLoginTransactions({ clock: { now: () => new Date(0) } });
    const pending = tx.start({ state: "s", nonce: "n", codeVerifier: "v" })!;
    expect(tx.take(pending.loginId)).toEqual({ state: "pending" });
    expect(tx.take(pending.loginId)).toEqual({ state: "pending" });
  });
});

describe("group mapping", () => {
  it.each([
    ["not JSON", "{", /not valid JSON/],
    ["not an object", "[]", /must be an object/],
    ["a non-list", '{"g":"agents:register"}', /must be a list/],
    ["an unknown scope", '{"g":["root"]}', /unknown scope root/],
    ["a misspelt read scope", '{"g":["audit:reads"]}', /unknown scope audit:reads/],
    ["a service-only scope", '{"g":["audit:write"]}', /audit:write is service-only/],
    ["no groups", "{}", /maps no groups/],
  ])("refuses %s", (_label, json, message) => {
    const parsed = parseGroupScopes(json);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.error).toMatch(message);
  });

  it("unions the scopes of every mapped group, ignoring others", () => {
    const mapping = parseGroupScopes(
      '{"a":["agents:register"],"b":["agents:revoke","agents:register"]}',
    );
    if (!mapping.ok) throw new Error(mapping.error);
    expect(scopesForGroups(["a", "b", "x", 7], mapping.value)).toEqual({
      matched: true,
      scopes: ["agents:register", "agents:revoke"],
    });
    expect(scopesForGroups("a", mapping.value)).toEqual({ matched: false, scopes: [] });
  });

  it("accepts the four read scopes, so a group can be read-only (ADR 0022 §3)", () => {
    const mapping = parseGroupScopes(
      '{"auditors":["audit:read"],"admins":["audit:read","revocations:read","policies:read","agents:read"]}',
    );
    if (!mapping.ok) throw new Error(mapping.error);
    expect(scopesForGroups(["auditors"], mapping.value)).toEqual({
      matched: true,
      scopes: ["audit:read"],
    });
    expect(scopesForGroups(["admins"], mapping.value).scopes).toEqual([
      "agents:read",
      "audit:read",
      "policies:read",
      "revocations:read",
    ]);
  });
});

describe("createOperatorSsoFromEnv", () => {
  const env = (overrides: Record<string, string> = {}) =>
    loadIdentityEnv({
      IDENTITY_ISSUER_SEED: "ab".repeat(32),
      IDENTITY_SERVICE_KEY: ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_"),
      SSO_ISSUER: issuer,
      SSO_CLIENT_ID: CLIENT_ID,
      SSO_CLIENT_SECRET: "s",
      SSO_REDIRECT_URL: REDIRECT,
      SSO_GROUP_SCOPES: '{"custos-admins":["agents:register"]}',
      SSO_ALLOW_HTTP_ISSUER: "true",
      ...overrides,
    });

  it("is null when SSO isn't configured", async () => {
    const result = await createOperatorSsoFromEnv(
      loadIdentityEnv({
        IDENTITY_ISSUER_SEED: "ab".repeat(32),
        IDENTITY_SERVICE_KEY: ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_"),
      }),
      keys,
    );
    expect(result).toEqual({ ok: true, value: null });
  });

  it("discovers the provider and builds a working login", async () => {
    const result = await createOperatorSsoFromEnv(env(), keys);
    if (!result.ok || result.value === null) throw new Error("expected SSO");
    const sso = result.value({ report: () => {}, log: () => {} });
    const started = await sso.start();
    expect(started?.authorizationUrl.startsWith(`${issuer}/authorize?`)).toBe(true);
  });

  it("refuses a bad group mapping at boot", async () => {
    const result = await createOperatorSsoFromEnv(
      env({ SSO_GROUP_SCOPES: '{"g":["audit:write"]}' }),
      keys,
    );
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/service-only/) });
  });

  it("refuses an unreachable provider at boot", async () => {
    const result = await createOperatorSsoFromEnv(
      env({ SSO_ISSUER: "http://127.0.0.1:9/realms/none" }),
      keys,
    );
    expect(result).toEqual({
      ok: false,
      error: expect.stringMatching(/cannot load the SSO provider's configuration/),
    });
  });
});

describe("dashboard sign-in (ADR 0022 §4)", () => {
  const RETURN = "http://localhost:4005/login/done";
  const ADMIN =
    '{"custos-admins":["agents:register","agents:revoke","credentials:write","policies:write","audit:read","revocations:read","policies:read","agents:read"],"custos-auditors":["audit:read"],"custos-writers":["agents:register","policies:write"]}';
  const READ_ONLY = ["agents:read", "audit:read", "policies:read", "revocations:read"];
  const controlPlane = createTestControlPlane(db);

  /** A clock that moves only when the test moves it; the provider's ID tokens use real time. */
  function movableClock() {
    let at = Date.now();
    return {
      now: () => new Date(at),
      advance: (ms: number) => {
        at += ms;
      },
    };
  }

  async function dashboard(
    options: {
      groupScopes?: string;
      returnUrls?: string | null;
      clock?: { now(): Date };
      reported?: AuditEvent[];
      logged?: object[];
      maxPending?: number;
    } = {},
  ) {
    const clock = options.clock ?? { now: () => new Date() };
    const config = await discoverProvider({
      issuer,
      clientId: CLIENT_ID,
      clientSecret: "test-secret",
      allowHttp: true,
    });
    const mapping = parseGroupScopes(options.groupScopes ?? ADMIN);
    if (!mapping.ok) throw new Error(mapping.error);
    const urls =
      options.returnUrls === null ? null : parseReturnUrls(options.returnUrls ?? `["${RETURN}"]`);
    if (urls !== null && !urls.ok) throw new Error(urls.error);
    const sso = createOperatorSso({
      config,
      redirectUrl: REDIRECT,
      groupScopes: mapping.value,
      ...(urls === null ? {} : { returnUrls: urls.value }),
      sessionMs: 8 * 3_600_000,
      keys,
      transactions: createLoginTransactions({
        clock,
        ...(options.maxPending === undefined ? {} : { maxPending: options.maxPending }),
      }),
      clock,
      report: (event) => options.reported?.push(event),
      log: (fields) => options.logged?.push(fields),
    });
    const app = await buildServer({
      db,
      controlPlaneAuth: controlPlane.guard,
      didDomain: "identity.custos.example",
      issuerKey: {
        keyProvider: createLocalKeyProvider({
          importedKeys: { issuer: new Uint8Array(32).fill(7) },
        }),
        keyId: "issuer",
      },
      statusAllocator: {
        allocate: async () => err({ code: "STATUS_ALLOCATION_FAILED", reason: "unused" }),
      },
      auditReporter: { report: () => {} },
      operatorSso: () => sso,
    });
    return { sso, app };
  }

  type App = Awaited<ReturnType<typeof dashboard>>["app"];

  const startLogin = (app: App, payload?: unknown) =>
    app.inject({
      method: "POST",
      url: "/operator/login",
      ...(payload === undefined ? {} : { payload: payload as object }),
    });

  /** Starts a dashboard login and brings the browser back from the provider. */
  async function signIn(
    app: App,
    claims: object = {},
    extraQuery = "",
  ): Promise<{ loginId: string; location: string; email: string }> {
    const started = await startLogin(app, { returnTo: RETURN });
    expect(started.statusCode).toBe(201);
    const { loginId, authorizationUrl } = started.json() as {
      loginId: string;
      authorizationUrl: string;
    };
    const url = new URL(authorizationUrl);
    const email = `dash-${randomUUID()}@acme.test`;
    oidcProvider.respondWith(
      good({ email, ...claims })(
        url.searchParams.get("nonce") ?? "",
        Math.floor(Date.now() / 1000),
      ),
    );
    const back = await app.inject({
      method: "GET",
      url: `/operator/callback?code=c&state=${url.searchParams.get("state")}${extraQuery}`,
    });
    expect(back.statusCode).toBe(303);
    expect(back.headers["cache-control"]).toBe("no-store");
    expect(back.headers["referrer-policy"]).toBe("no-referrer");
    return { loginId, location: String(back.headers.location), email };
  }

  const codeOf = (location: string): string => new URL(location).searchParams.get("code") ?? "";

  const release = (app: App, loginId: string, payload?: unknown) =>
    app.inject({
      method: "POST",
      url: `/operator/login/${loginId}/release`,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });

  async function scopesOf(operatorKey: string): Promise<string[]> {
    const authenticated = await createApiKeyAuthenticator({
      keys,
      clock: { now: () => new Date() },
    }).authenticate({ headers: { authorization: `Bearer ${operatorKey}` } });
    if (!authenticated.ok) throw new Error("key does not authenticate");
    return [...authenticated.value.scopes].sort();
  }

  const keyNamed = async (email: string) => (await keys.list()).some((row) => row.name === email);

  describe("returnTo is checked exactly", () => {
    it.each([
      ["a foreign host", "http://evil.example/login/done"],
      ["a lookalike prefix", "http://localhost:4005/login/doneX"],
      ["a lookalike host", "http://localhost:4005.evil.example/login/done"],
      ["an extra path", "http://localhost:4005/login/done/extra"],
      ["a parent path", "http://localhost:4005/login/done/.."],
      ["an encoded path", "http://localhost:4005/login/%64one"],
      ["an encoded whole address", encodeURIComponent(RETURN)],
      ["a trailing slash", `${RETURN}/`],
      ["an added query", `${RETURN}?next=/`],
      ["an added fragment", `${RETURN}#x`],
      ["another scheme", "https://localhost:4005/login/done"],
      ["another port", "http://localhost:4006/login/done"],
      ["the default port written out", "http://localhost:80/login/done"],
      ["upper case", "HTTP://LOCALHOST:4005/login/done"],
      ["another loopback name", "http://127.0.0.1:4005/login/done"],
      ["surrounding space", ` ${RETURN}`],
      ["an empty value", ""],
    ])("refuses %s before anything starts or redirects", async (_label, returnTo) => {
      // One slot: a refusal that started a login would fill it.
      const { app } = await dashboard({ maxPending: 1 });
      const refused = await startLogin(app, { returnTo });
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toEqual({ error: { code: "RETURN_URL_NOT_ALLOWED" } });
      expect(refused.headers.location).toBeUndefined();
      expect((await startLogin(app, { returnTo: RETURN })).statusCode).toBe(201);
    });

    it("refuses every returnTo when SSO_RETURN_URLS is not set", async () => {
      const { app } = await dashboard({ returnUrls: null });
      const refused = await startLogin(app, { returnTo: RETURN });
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toEqual({ error: { code: "RETURN_URL_NOT_ALLOWED" } });
    });

    it.each([
      ["a returnTo that is not a string", { returnTo: 4005 }],
      ["a caller asking for scopes", { returnTo: RETURN, scopes: ["agents:revoke"] }],
      ["any other field", { readOnly: false }],
      ["a list", [RETURN]],
    ])("refuses %s: nothing can widen a sign-in", async (_label, body) => {
      const { app } = await dashboard();
      const refused = await startLogin(app, body);
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toEqual({ error: { code: "INVALID_INPUT" } });
    });

    it("leaves the terminal's login unchanged: no body, or an empty one", async () => {
      const { app } = await dashboard();
      expect((await startLogin(app)).statusCode).toBe(201);
      expect((await startLogin(app, {})).statusCode).toBe(201);
    });

    it("refuses an unchecked returnTo inside the service too", async () => {
      const { sso } = await dashboard();
      await expect(sso.start({ returnTo: "http://evil.example/" })).rejects.toThrow(
        /not checked against SSO_RETURN_URLS/,
      );
    });
  });

  describe("a successful dashboard sign-in", () => {
    it("returns to returnTo with a one-time code, then releases a read-only key once for it", async () => {
      const reported: AuditEvent[] = [];
      const { app } = await dashboard({ reported });
      const { loginId, location, email } = await signIn(app);

      expect(location.startsWith(`${RETURN}?code=`)).toBe(true);
      const code = codeOf(location);
      expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(code).not.toBe(loginId);
      expect(code).not.toContain(loginId);
      expect([...new URL(location).searchParams.keys()]).toEqual(["code"]);
      // No key exists until the code is presented.
      expect(await keyNamed(email)).toBe(false);
      expect(reported).toEqual([]);

      // The terminal's poll never releases a dashboard login, and leaves it be.
      const polled = await app.inject({ method: "GET", url: `/operator/login/${loginId}` });
      expect(polled.statusCode).toBe(404);
      expect(polled.json()).toEqual({ error: { code: "UNKNOWN_LOGIN" } });

      const released = await release(app, loginId, { loginCode: code });
      expect(released.statusCode).toBe(200);
      expect(released.headers["cache-control"]).toBe("no-store");
      const body = released.json() as { operatorKey: string; name: string; scopes: string[] };
      expect(body.name).toBe(email);
      expect(body.operatorKey).toMatch(/^custos_operator_/);
      expect(body.operatorKey).not.toContain(code);
      expect([...body.scopes].sort()).toEqual(READ_ONLY);
      expect(await scopesOf(body.operatorKey)).toEqual(READ_ONLY);
      expect(reported).toEqual([
        expect.objectContaining({
          action: "operator.login",
          policy: { rule: "operator-sso-dashboard", decision: "allow" },
          principal: expect.objectContaining({ kind: "operator", name: email }),
        }),
      ]);

      // Identity itself: the key reads agents and cannot register one.
      const auth = { authorization: `Bearer ${body.operatorKey}` };
      expect((await app.inject({ method: "GET", url: "/agents", headers: auth })).statusCode).toBe(
        200,
      );
      const register = await app.inject({
        method: "POST",
        url: "/agents",
        headers: auth,
        payload: { publicKey: "z6Mk", proof: "p" },
      });
      expect(register.statusCode).toBe(401);
      expect(register.json()).toEqual({ error: { code: "UNAUTHORIZED" } });

      // Replayed: refused, and no second key.
      const replayed = await release(app, loginId, { loginCode: code });
      expect(replayed.statusCode).toBe(401);
      expect(replayed.json()).toEqual({ error: { code: "INVALID_LOGIN_CODE" } });
      expect((await keys.list()).filter((row) => row.name === email)).toHaveLength(1);
    });

    it("takes where to return from the login, never from the provider's redirect", async () => {
      const { app } = await dashboard();
      const { location } = await signIn(app, {}, "&returnTo=https%3A%2F%2Fevil.example%2F");
      expect(new URL(location).origin + new URL(location).pathname).toBe(RETURN);
    });

    it("gives an auditor's group exactly its own read scope", async () => {
      const { app } = await dashboard();
      const { loginId, location } = await signIn(app, { groups: ["custos-auditors"] });
      const released = await release(app, loginId, { loginCode: codeOf(location) });
      expect((released.json() as { scopes: string[] }).scopes).toEqual(["audit:read"]);
    });
  });

  describe("a refused dashboard sign-in returns with the reason, and makes no key", () => {
    it.each([
      ["a group with only write scopes", { groups: ["custos-writers"] }, "NO_READ_SCOPE"],
      ["no mapped group", { groups: ["engineering"] }, "NO_MAPPED_GROUP"],
      ["a token for someone else", { aud: "someone-else" }, "TOKEN_REJECTED"],
    ])("%s", async (_label, claims, reason) => {
      const { app } = await dashboard();
      const { loginId, location, email } = await signIn(app, claims);
      expect(location).toBe(`${RETURN}?error=${reason}`);
      expect(await keyNamed(email)).toBe(false);
      // Nothing to release either.
      expect((await release(app, loginId, { loginCode: "A".repeat(43) })).statusCode).toBe(401);
      expect(await keyNamed(email)).toBe(false);
    });

    it("while the same write-only group still gets its key through the terminal", async () => {
      const { sso } = await dashboard();
      const { outcome } = await login(sso, good({ groups: ["custos-writers"] }));
      expect(outcome.state).toBe("complete");
      if (outcome.state === "complete") {
        expect(await scopesOf(outcome.login.operatorKey)).toEqual([
          "agents:register",
          "policies:write",
        ]);
      }
    });
  });

  describe("the one-time code", () => {
    it.each([
      ["missing", {}],
      ["no body at all", undefined],
      ["too short", { loginCode: "abc" }],
      ["not base64url", { loginCode: `${"A".repeat(42)}=` }],
      ["sent under another name", { code: "A".repeat(43) }],
    ])("is refused when %s, as a bad request", async (_label, payload) => {
      const { app } = await dashboard();
      const { loginId, location } = await signIn(app);
      const refused = await release(app, loginId, payload);
      expect(refused.statusCode).toBe(400);
      expect(refused.json()).toEqual({ error: { code: "INVALID_INPUT" } });
      // A malformed request is not a guess: the real code still works.
      expect((await release(app, loginId, { loginCode: codeOf(location) })).statusCode).toBe(200);
    });

    it("is refused when wrong, and the login then ends: no second guess", async () => {
      const { app } = await dashboard();
      const { loginId, location, email } = await signIn(app);
      const wrong = await release(app, loginId, { loginCode: "A".repeat(43) });
      expect(wrong.statusCode).toBe(401);
      expect(wrong.json()).toEqual({ error: { code: "INVALID_LOGIN_CODE" } });
      const right = await release(app, loginId, { loginCode: codeOf(location) });
      expect(right.statusCode).toBe(401);
      expect(right.json()).toEqual({ error: { code: "INVALID_LOGIN_CODE" } });
      expect(await keyNamed(email)).toBe(false);
    });

    it("is refused once a minute has passed, and accepted just before", async () => {
      const clock = movableClock();
      const { app } = await dashboard({ clock });

      const late = await signIn(app);
      clock.advance(LOGIN_CODE_TTL_MS);
      const expired = await release(app, late.loginId, { loginCode: codeOf(late.location) });
      expect(expired.statusCode).toBe(401);
      expect(expired.json()).toEqual({ error: { code: "INVALID_LOGIN_CODE" } });
      expect(await keyNamed(late.email)).toBe(false);

      const inTime = await signIn(app);
      clock.advance(LOGIN_CODE_TTL_MS - 1);
      expect(
        (await release(app, inTime.loginId, { loginCode: codeOf(inTime.location) })).statusCode,
      ).toBe(200);
    });

    it("is refused for a different login, which then ends; its own login is untouched", async () => {
      const { app } = await dashboard();
      const a = await signIn(app);
      const b = await signIn(app);
      const crossed = await release(app, b.loginId, { loginCode: codeOf(a.location) });
      expect(crossed.statusCode).toBe(401);
      expect(crossed.json()).toEqual({ error: { code: "INVALID_LOGIN_CODE" } });
      expect((await release(app, b.loginId, { loginCode: codeOf(b.location) })).statusCode).toBe(
        401,
      );
      expect((await release(app, a.loginId, { loginCode: codeOf(a.location) })).statusCode).toBe(
        200,
      );
    });

    it("is refused for a login that was never started, or is malformed", async () => {
      const { app } = await dashboard();
      const code = { loginCode: "A".repeat(43) };
      expect((await release(app, "0".repeat(32), code)).statusCode).toBe(401);
      expect((await release(app, "not-an-id", code)).statusCode).toBe(400);
    });

    it("cannot release a terminal login's key", async () => {
      const { app } = await dashboard();
      const { loginId, authorizationUrl } = (await startLogin(app)).json() as {
        loginId: string;
        authorizationUrl: string;
      };
      const url = new URL(authorizationUrl);
      oidcProvider.respondWith(
        good()(url.searchParams.get("nonce") ?? "", Math.floor(Date.now() / 1000)),
      );
      const back = await app.inject({
        method: "GET",
        url: `/operator/callback?code=c&state=${url.searchParams.get("state")}`,
      });
      expect(back.statusCode).toBe(200);
      const attempt = await release(app, loginId, { loginCode: "A".repeat(43) });
      expect(attempt.statusCode).toBe(401);
      expect(attempt.body).not.toContain("custos_operator_");
    });

    it("is never logged, and neither is the key", async () => {
      const logged: object[] = [];
      const { app } = await dashboard({ logged });
      const chunks: string[] = [];
      const logger = createLogger(
        {},
        new Writable({
          write(chunk, _encoding, done) {
            chunks.push(String(chunk));
            done();
          },
        }),
      );

      const refused = await signIn(app);
      await release(app, refused.loginId, { loginCode: "A".repeat(43) });
      const accepted = await signIn(app);
      const code = codeOf(accepted.location);
      const released = await release(app, accepted.loginId, { loginCode: code });
      const { operatorKey } = released.json() as { operatorKey: string };

      // What identity logs about these logins, through the real logger, plus
      // a careless log of the request and response bodies.
      for (const fields of logged) logger.warn(fields, "sso");
      logger.info({ body: { loginCode: code }, res: { operatorKey } }, "careless");
      const output = chunks.join("");
      expect(logged.length).toBeGreaterThan(0);
      expect(output).not.toContain(code);
      expect(output).not.toContain(codeOf(refused.location));
      expect(output).not.toContain(operatorKey);
      expect(output).toContain("[REDACTED]");
    });
  });

  it("boots with SSO_RETURN_URLS and refuses a malformed one even past the env check", async () => {
    const env = (overrides: Record<string, string> = {}): Env =>
      loadIdentityEnv({
        IDENTITY_ISSUER_SEED: "ab".repeat(32),
        IDENTITY_SERVICE_KEY: ["custos", "service", "0123456789abcdef", "k".repeat(43)].join("_"),
        SSO_ISSUER: issuer,
        SSO_CLIENT_ID: CLIENT_ID,
        SSO_CLIENT_SECRET: "s",
        SSO_REDIRECT_URL: REDIRECT,
        SSO_GROUP_SCOPES: '{"custos-admins":["agents:read"]}',
        SSO_ALLOW_HTTP_ISSUER: "true",
        ...overrides,
      });
    const booted = await createOperatorSsoFromEnv(env({ SSO_RETURN_URLS: `["${RETURN}"]` }), keys);
    if (!booted.ok || booted.value === null) throw new Error("expected SSO");
    const sso = booted.value({ report: () => {}, log: () => {} });
    expect(sso.allowsReturnTo(RETURN)).toBe(true);
    expect(sso.allowsReturnTo(`${RETURN}/`)).toBe(false);

    const unset = await createOperatorSsoFromEnv(env(), keys);
    if (!unset.ok || unset.value === null) throw new Error("expected SSO");
    expect(unset.value({ report: () => {}, log: () => {} }).allowsReturnTo(RETURN)).toBe(false);

    expect(await createOperatorSsoFromEnv({ ...env(), SSO_RETURN_URLS: "[]" }, keys)).toEqual({
      ok: false,
      error: expect.stringMatching(/SSO_RETURN_URLS/),
    });
  });
});

describe("read-only scopes", () => {
  it("keeps only the four read scopes", () => {
    expect(
      readOnly(["agents:register", "audit:read", "policies:write", "agents:read", "agents:revoke"]),
    ).toEqual(["audit:read", "agents:read"]);
    expect(readOnly(["agents:register", "credentials:write"])).toEqual([]);
  });

  it("accepts an IPv6 loopback over http", () => {
    expect(parseReturnUrls('["http://[::1]:4005/login/done"]').ok).toBe(true);
  });
});

describe("dashboard login transactions", () => {
  const awaiting = {
    codeHash: Buffer.alloc(32, 1),
    codeExpiresAt: 60_000,
    name: "n",
    scopes: ["audit:read"] as const,
  };

  it("never turn a terminal login into a dashboard one", () => {
    const tx = createLoginTransactions({ clock: { now: () => new Date(0) } });
    const pending = tx.start({ state: "s", nonce: "n", codeVerifier: "v" })!;
    tx.awaitRelease(pending.loginId, awaiting);
    expect(tx.findByState("s")?.loginId).toBe(pending.loginId);
    expect(tx.release("unknown-id", Buffer.alloc(32, 1))).toBeNull();
  });

  it("refuse a code of the wrong length without comparing it", () => {
    const tx = createLoginTransactions({ clock: { now: () => new Date(0) } });
    const pending = tx.start({ state: "s", nonce: "n", codeVerifier: "v", returnTo: "r" })!;
    tx.awaitRelease(pending.loginId, awaiting);
    expect(tx.findByState("s")).toBeNull();
    expect(tx.release(pending.loginId, Buffer.alloc(16, 1))).toBeNull();
  });

  it("end with their code", () => {
    let now = 0;
    const tx = createLoginTransactions({ clock: { now: () => new Date(now) } });
    const pending = tx.start({ state: "s", nonce: "n", codeVerifier: "v", returnTo: "r" })!;
    tx.awaitRelease(pending.loginId, awaiting);
    now = 60_000;
    expect(tx.release(pending.loginId, Buffer.alloc(32, 1))).toBeNull();
  });

  it("release the login's name and scopes for the matching code", () => {
    const tx = createLoginTransactions({ clock: { now: () => new Date(0) } });
    const pending = tx.start({ state: "s", nonce: "n", codeVerifier: "v", returnTo: "r" })!;
    tx.awaitRelease(pending.loginId, awaiting);
    expect(tx.release(pending.loginId, Buffer.alloc(32, 1))).toEqual({
      name: "n",
      scopes: ["audit:read"],
    });
  });
});

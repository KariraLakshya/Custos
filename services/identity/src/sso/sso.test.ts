import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { AuditEvent } from "@custos/audit-client";
import { createApiKeyAuthenticator, createApiKeyStore } from "@custos/control-plane-auth";
import { createLocalKeyProvider, err } from "@custos/core";
import { createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb } from "../db/client.js";
import { buildServer } from "../server.js";
import { loadIdentityEnv } from "../env.js";
import { createOperatorSsoFromEnv, discoverProvider } from "./boot.js";
import { parseGroupScopes, scopesForGroups } from "./config.js";
import { createOperatorSso, type OperatorSso } from "./sso.js";
import { createLoginTransactions } from "./transactions.js";

/**
 * Operator SSO (ADR 0010) against a minimal OIDC provider run inside the
 * test. A real provider never issues the broken tokens the build plan's
 * DONE check needs (bad signature, wrong issuer, audience or nonce,
 * expired), so this one does, signed with node:crypto (ES256). The happy
 * path against real Keycloak is in sso-keycloak.test.ts.
 */

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);
const keys = createApiKeyStore(db);
const CLIENT_ID = "custos-identity";
const REDIRECT = "http://127.0.0.1:5899/operator/callback";

const signing = generateKeyPairSync("ec", { namedCurve: "P-256" });
const impostor = generateKeyPairSync("ec", { namedCurve: "P-256" });
const b64 = (value: object | Buffer) =>
  (Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value))).toString("base64url");

function jwt(claims: object, key: KeyObject = signing.privateKey): string {
  const head = `${b64({ alg: "ES256", kid: "k1", typ: "JWT" })}.${b64(claims)}`;
  return `${head}.${b64(sign("sha256", Buffer.from(head), { key, dsaEncoding: "ieee-p1363" }))}`;
}

let provider: Server;
let issuer: string;
/** The ID token the provider's token endpoint returns next. */
let nextIdToken = "";

beforeAll(async () => {
  provider = createServer((req, res) => {
    const json = (body: unknown) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(body));
    };
    if (req.url === "/.well-known/openid-configuration") {
      return json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        code_challenge_methods_supported: ["S256"],
      });
    }
    if (req.url === "/jwks") {
      return json({
        keys: [
          { ...signing.publicKey.export({ format: "jwk" }), kid: "k1", alg: "ES256", use: "sig" },
        ],
      });
    }
    if (req.url === "/token" && req.method === "POST") {
      req.resume();
      return req.on("end", () =>
        json({ access_token: "at", token_type: "Bearer", expires_in: 300, id_token: nextIdToken }),
      );
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((done) => provider.listen(0, "127.0.0.1", done));
  issuer = `http://127.0.0.1:${(provider.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise((done) => provider.close(done));
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
  nextIdToken = jwt(claims(url.searchParams.get("nonce") ?? "", now), key);
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
    ["a bad signature (signed by an unknown key)", good(), impostor.privateKey],
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
      key,
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
    nextIdToken = jwt(
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
    nextIdToken = jwt(
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

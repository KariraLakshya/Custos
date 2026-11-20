import { randomUUID } from "node:crypto";
import { createLocalKeyProvider, createLocalSecretCipher, err, ok } from "@custos/core";
import { createApiKeyStore } from "@custos/control-plane-auth";
import {
  buildServer as buildIdentityServer,
  createDb as createIdentityDb,
  createLoginTransactions,
  createOperatorSso,
  discoverProvider,
  parseGroupScopes,
  parseReturnUrls,
} from "@custos/identity";
import {
  buildServer as buildRevocationServer,
  createDb as createRevocationDb,
} from "@custos/revocation";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { startTestOidcProvider, type TestOidcProvider } from "@custos/testing/oidc-provider";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb } from "./db/client.js";
import type { RevocationCache } from "./revocation/cache.js";
import { buildServer } from "./server.js";

/**
 * ADR 0022 §4: a dashboard sign-in's key can only ever read. An admin, whose
 * group may do everything, signs in to the dashboard through identity's real
 * SSO flow (an in-test OIDC provider stands in for the company login); the
 * key identity releases is then tried on the write routes of every service.
 * The same admin's terminal key is the control: the same requests get past
 * the key check, so a refusal here is the key's scopes, not the request.
 */

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const vaultDb = createDb(databaseUrl);
const identityDb = createIdentityDb(databaseUrl);
const revocationDb = createRevocationDb(databaseUrl);
const controlPlane = createTestControlPlane(vaultDb);
const RETURN = "http://localhost:4005/login/done";
const REDIRECT = "http://127.0.0.1:5899/operator/callback";
const ADMIN_SCOPES = [
  "agents:register",
  "agents:revoke",
  "credentials:write",
  "policies:write",
  "audit:read",
  "revocations:read",
  "policies:read",
  "agents:read",
];

let oidc: TestOidcProvider;
let identity: Awaited<ReturnType<typeof buildIdentityServer>>;
let revocation: Awaited<ReturnType<typeof buildRevocationServer>>;
let vault: Awaited<ReturnType<typeof buildServer>>;

const freshEmptyRevocationCache = (): RevocationCache => ({
  verdict: () => "ok",
  trackAgent: () => ok(undefined),
  isStale: () => false,
  status: () => ({ revokedCount: 0, freshAsOf: new Date().toISOString(), stale: false }),
  acceptTombstone: async () => ok("noop"),
  resync: async () => ok(0),
});

beforeAll(async () => {
  oidc = await startTestOidcProvider();
  const config = await discoverProvider({
    issuer: oidc.issuer,
    clientId: "custos-identity",
    clientSecret: "test-secret",
    allowHttp: true,
  });
  const groupScopes = parseGroupScopes(JSON.stringify({ "custos-admins": ADMIN_SCOPES }));
  const returnUrls = parseReturnUrls(JSON.stringify([RETURN]));
  if (!groupScopes.ok || !returnUrls.ok) throw new Error("test configuration");
  const clock = { now: () => new Date() };
  identity = await buildIdentityServer({
    db: identityDb,
    controlPlaneAuth: controlPlane.guard,
    didDomain: "identity.custos.example",
    issuerKey: {
      keyProvider: createLocalKeyProvider({ importedKeys: { issuer: new Uint8Array(32).fill(3) } }),
      keyId: "issuer",
    },
    statusAllocator: {
      allocate: async () => err({ code: "STATUS_ALLOCATION_FAILED", reason: "unused" }),
    },
    auditReporter: { report: () => {} },
    operatorSso: () =>
      createOperatorSso({
        config,
        redirectUrl: REDIRECT,
        groupScopes: groupScopes.value,
        returnUrls: returnUrls.value,
        sessionMs: 3_600_000,
        keys: createApiKeyStore(identityDb),
        transactions: createLoginTransactions({ clock }),
        clock,
      }),
  });
  revocation = await buildRevocationServer({
    db: revocationDb,
    signingKey: {
      keyProvider: createLocalKeyProvider({
        importedKeys: { signing: new Uint8Array(32).fill(4) },
      }),
      keyId: "signing",
    },
    auditReporter: { report: () => {} },
    controlPlaneAuth: controlPlane.guard,
    didDomain: "127.0.0.1:4503",
  });
  vault = await buildServer({
    db: vaultDb,
    controlPlaneAuth: controlPlane.guard,
    serviceKey: await controlPlane.key("service", ["audit:write"]),
    cipher: createLocalSecretCipher(new Uint8Array(32).fill(5)),
    revocation: freshEmptyRevocationCache(),
  });
});

afterAll(async () => {
  await identity?.close();
  await revocation?.close();
  await vault?.close();
  await oidc?.close();
  await vaultDb.$client.end();
  await identityDb.$client.end();
  await revocationDb.$client.end();
});

/** Brings an admin back from the company login: the dashboard's code, or the terminal's poll. */
async function adminSignsIn(returnTo?: string): Promise<string> {
  const started = await identity.inject({
    method: "POST",
    url: "/operator/login",
    ...(returnTo === undefined ? {} : { payload: { returnTo } }),
  });
  const { loginId, authorizationUrl } = started.json() as {
    loginId: string;
    authorizationUrl: string;
  };
  const url = new URL(authorizationUrl);
  const now = Math.floor(Date.now() / 1000);
  oidc.respondWith({
    iss: oidc.issuer,
    aud: "custos-identity",
    sub: `admin-${randomUUID()}`,
    email: `admin-${randomUUID()}@acme.test`,
    groups: ["custos-admins"],
    nonce: url.searchParams.get("nonce"),
    iat: now,
    exp: now + 300,
  });
  const back = await identity.inject({
    method: "GET",
    url: `/operator/callback?code=c&state=${url.searchParams.get("state")}`,
  });
  if (returnTo === undefined) {
    const polled = await identity.inject({ method: "GET", url: `/operator/login/${loginId}` });
    return (polled.json() as { operatorKey: string }).operatorKey;
  }
  const loginCode = new URL(String(back.headers.location)).searchParams.get("code");
  const released = await identity.inject({
    method: "POST",
    url: `/operator/login/${loginId}/release`,
    payload: { loginCode },
  });
  return (released.json() as { operatorKey: string }).operatorKey;
}

/** Every write route, each with a request the key check is the only thing to stop. */
const writes = [
  {
    name: "vault POST /policies",
    send: (key: string) =>
      vault.inject({
        method: "POST",
        url: "/policies",
        headers: bearer(key),
        payload: { agentDid: "not-a-did" },
      }),
  },
  {
    name: "vault POST /credentials",
    send: (key: string) =>
      vault.inject({
        method: "POST",
        url: "/credentials",
        headers: bearer(key),
        payload: {},
      }),
  },
  {
    name: "revocation POST /revocations",
    send: (key: string) =>
      revocation.inject({
        method: "POST",
        url: "/revocations",
        headers: bearer(key),
        payload: { agentId: "not-a-uuid" },
      }),
  },
  {
    name: "identity POST /agents",
    send: (key: string) =>
      identity.inject({
        method: "POST",
        url: "/agents",
        headers: bearer(key),
        payload: { publicKey: "z6Mk", proof: "p" },
      }),
  },
];

describe("an admin's dashboard sign-in key (ADR 0022 §4)", () => {
  let dashboardKey: string;
  let terminalKey: string;
  beforeAll(async () => {
    dashboardKey = await adminSignsIn(RETURN);
    terminalKey = await adminSignsIn();
  });

  it.each(writes.map((write) => [write.name, write] as const))(
    "is refused by %s",
    async (_name, write) => {
      const refused = await write.send(dashboardKey);
      expect(refused.statusCode).toBe(401);
      expect(refused.json()).toEqual({ error: { code: "UNAUTHORIZED" } });
      // Control: the same admin's terminal key gets past the key check.
      expect((await write.send(terminalKey)).statusCode).not.toBe(401);
    },
  );

  it("is accepted by identity GET /agents and vault GET /policies", async () => {
    const agents = await identity.inject({
      method: "GET",
      url: "/agents",
      headers: bearer(dashboardKey),
    });
    expect(agents.statusCode).toBe(200);
    const grants = await vault.inject({
      method: "GET",
      url: "/policies",
      headers: bearer(dashboardKey),
    });
    expect(grants.statusCode).toBe(200);
  });
});

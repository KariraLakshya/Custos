import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createApiKeyAuthenticator, createApiKeyStore } from "@custos/control-plane-auth";
import { createLocalKeyProvider, err } from "@custos/core";
import { createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb } from "../db/client.js";
import { buildServer } from "../server.js";
import { discoverProvider } from "./boot.js";
import { parseGroupScopes } from "./config.js";
import { createOperatorSso } from "./sso.js";
import { createLoginTransactions } from "./transactions.js";

/**
 * Operator SSO against real Keycloak (ADR 0010 §5): the pinned image with
 * the checked-in realm. The test plays the browser: it fetches Keycloak's
 * real login page, posts the realm's throwaway test user's credentials,
 * and follows the redirect into the identity service. Needs Docker.
 */

const repoRoot = resolve(__dirname, "../../../..");
const images = JSON.parse(readFileSync(join(repoRoot, "infra/sso/images.json"), "utf8")) as {
  keycloak: string;
};
const PORT = 8181;
const ISSUER = `http://localhost:${PORT}/realms/custos`;
// Registered in infra/sso/realm-custos.json.
const REDIRECT = "http://127.0.0.1:5801/operator/callback";
const CONTAINER = "custos-keycloak-test";

const db = createDb(process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos");
const keys = createApiKeyStore(db);
const controlPlane = createTestControlPlane(db);
let app: Awaited<ReturnType<typeof buildServer>>;

beforeAll(async () => {
  execFileSync("docker", ["rm", "-f", CONTAINER], { stdio: "ignore" });
  execFileSync("docker", [
    "run",
    "-d",
    "--rm",
    "--name",
    CONTAINER,
    "-p",
    `${PORT}:${PORT}`,
    "-e",
    `KC_HOSTNAME=http://localhost:${PORT}`,
    "-v",
    `${join(repoRoot, "infra/sso/realm-custos.json")}:/opt/keycloak/data/import/realm-custos.json:ro`,
    images.keycloak,
    "start-dev",
    "--import-realm",
    `--http-port=${PORT}`,
  ]);
  for (let attempt = 0; ; attempt += 1) {
    const ready = await fetch(`${ISSUER}/.well-known/openid-configuration`).then(
      (response) => response.ok,
      () => false,
    );
    if (ready) break;
    if (attempt >= 120) throw new Error("Keycloak never became ready");
    await new Promise((done) => setTimeout(done, 1_000));
  }

  const config = await discoverProvider({
    issuer: ISSUER,
    clientId: "custos-identity",
    clientSecret: "custos-dev-sso-client-secret-not-for-production",
    allowHttp: true,
  });
  const groupScopes = parseGroupScopes(
    '{"custos-admins":["agents:register","agents:revoke","credentials:write","policies:write"]}',
  );
  if (!groupScopes.ok) throw new Error(groupScopes.error);
  app = await buildServer({
    db,
    controlPlaneAuth: controlPlane.guard,
    didDomain: "identity.custos.example",
    issuerKey: {
      keyProvider: createLocalKeyProvider({ importedKeys: { issuer: new Uint8Array(32).fill(9) } }),
      keyId: "issuer",
    },
    statusAllocator: {
      allocate: async () => err({ code: "STATUS_ALLOCATION_FAILED", reason: "unused" }),
    },
    auditReporter: { report: () => {} },
    operatorSso: ({ report, log }) =>
      createOperatorSso({
        config,
        redirectUrl: REDIRECT,
        groupScopes: groupScopes.value,
        sessionMs: 8 * 3_600_000,
        keys,
        transactions: createLoginTransactions({ clock: { now: () => new Date() } }),
        clock: { now: () => new Date() },
        report,
        log,
      }),
  });
}, 300_000);

afterAll(async () => {
  execFileSync("docker", ["rm", "-f", CONTAINER], { stdio: "ignore" });
  await app?.close();
  await db.$client.end();
});

/** Plays the browser: Keycloak's login page, credentials, and the redirect back to Custos. */
async function signIn(username: string, password: string) {
  const started = (await app.inject({ method: "POST", url: "/operator/login" })).json() as {
    loginId: string;
    authorizationUrl: string;
  };
  const cookies = new Map<string, string>();
  const remember = (response: Response) => {
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(";");
      const [name, ...value] = (pair ?? "").split("=");
      if (name) cookies.set(name, value.join("="));
    }
  };
  const cookieHeader = () => [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");

  const page = await fetch(started.authorizationUrl, { redirect: "manual" });
  remember(page);
  const html = await page.text();
  const action = /<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/.exec(html)?.[1];
  if (!action) throw new Error("no Keycloak login form");

  const submitted = await fetch(action.replaceAll("&amp;", "&"), {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie: cookieHeader() },
    body: new URLSearchParams({ username, password, credentialId: "" }).toString(),
  });
  const location = submitted.headers.get("location");
  const callback =
    location?.startsWith(REDIRECT) === true
      ? await app.inject({ method: "GET", url: `/operator/callback${new URL(location).search}` })
      : null;
  const polled = await app.inject({ method: "GET", url: `/operator/login/${started.loginId}` });
  return { submitted, location, callback, polled };
}

describe("operator SSO with real Keycloak (ADR 0010)", () => {
  it("signs alice (custos-admins) in and issues her a working operator key", async () => {
    const { callback, polled } = await signIn("alice", "alice-dev-password");
    expect(callback?.statusCode).toBe(200);
    expect(callback?.body).toContain("Signed in to Custos as alice@custos.local");
    expect(polled.statusCode).toBe(200);
    const { operatorKey, name } = polled.json() as { operatorKey: string; name: string };
    expect(name).toBe("alice@custos.local");

    const authenticated = await createApiKeyAuthenticator({
      keys,
      clock: { now: () => new Date() },
    }).authenticate({ headers: { authorization: `Bearer ${operatorKey}` } });
    expect(authenticated.ok && [...authenticated.value.scopes].sort()).toEqual([
      "agents:register",
      "agents:revoke",
      "credentials:write",
      "policies:write",
    ]);
  });

  it("refuses bob, who is in no mapped group, and issues nothing", async () => {
    const { callback, polled } = await signIn("bob", "bob-dev-password");
    expect(callback?.statusCode).toBe(401);
    expect(polled.statusCode).toBe(401);
    expect(polled.json()).toEqual({ error: { code: "NO_MAPPED_GROUP" } });
  });

  it("never reaches Custos with a wrong password", async () => {
    const { location, callback, polled } = await signIn("alice", "wrong-password");
    expect(location ?? "").not.toContain("/operator/callback");
    expect(callback).toBeNull();
    expect(polled.statusCode).toBe(202);
  });
});

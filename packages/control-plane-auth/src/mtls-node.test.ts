import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApiKeyAuthenticator } from "./authenticator.js";
import { resolveEnvoyListener, resolveOutgoingServiceAuth } from "./boot.js";
import { principalOf, requireScope } from "./fastify.js";
import { createLockout } from "./lockout.js";
import { createMtlsFetch } from "./mtls-fetch.js";
import {
  createEnvoyOnlyTlsListener,
  loadMtlsIdentity,
  type EnvoyOnlyTlsListener,
  type MtlsIdentity,
} from "./mtls-server.js";
import { serviceUri, withForwardedServiceCertificates } from "./mtls.js";

/**
 * The Node side of ADR 0009 with real certificates and real TLS, no Envoy:
 * a client presenting Envoy's upstream certificate stands in for Envoy.
 * Certificates come from the real generator (Docker, like the proxy test).
 */

const repoRoot = resolve(__dirname, "../../..");
let dir: string;
// Set once the certificates exist: "now" must be inside their validity.
let NOW: Date;

function files(name: string, ca = "ca.crt") {
  return {
    certFile: join(dir, `${name}.crt`),
    keyFile: join(dir, `${name}.key`),
    caFile: join(dir, ca),
  };
}

function identity(name: string, expectedUri?: string): MtlsIdentity {
  const loaded = loadMtlsIdentity(files(name), {
    now: NOW,
    ...(expectedUri ? { expectedUri } : {}),
  });
  if (!loaded.ok) throw new Error(loaded.error);
  return loaded.value;
}

let app: FastifyInstance;
let listener: EnvoyOnlyTlsListener;
let tlsUrl: string;
let plainUrl: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "custos-mtls-node-"));
  execFileSync("node", [join(repoRoot, "infra/mtls/certs.mjs"), dir, "--with-negative-fixtures"]);
  NOW = new Date();

  // A guarded route exactly as the services wire it, with no API keys at
  // all: the only way in is a certificate Envoy forwarded.
  listener = createEnvoyOnlyTlsListener(identity("revocation-server"));
  app = Fastify({ serverFactory: listener.serverFactory });
  const clock = { now: () => NOW };
  const authenticator = withForwardedServiceCertificates(
    createApiKeyAuthenticator({ keys: { findById: async () => null }, clock }),
  );
  app.post(
    "/agents",
    {
      preHandler: requireScope({
        authenticator,
        lockout: createLockout({ clock }),
        scope: "status:allocate",
      }),
    },
    async (request) => ({ by: principalOf(request).id }),
  );
  await app.listen({ port: 0, host: "127.0.0.1" });
  plainUrl = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  tlsUrl = `https://localhost:${await listener.listen(0, "127.0.0.1")}`;
}, 180_000);

afterAll(async () => {
  await listener?.close();
  await app?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

const XFCC = "x-forwarded-client-cert";

describe("Envoy-only TLS listener + forwarded identity (ADR 0009 part B)", () => {
  it("authenticates the service Envoy forwarded, on a connection from Envoy", async () => {
    const asEnvoy = createMtlsFetch(identity("envoy-upstream"));
    const response = await asEnvoy(`${tlsUrl}/agents`, {
      method: "POST",
      headers: { [XFCC]: `URI=${serviceUri("identity")}` },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ by: serviceUri("identity") });
  });

  it("refuses a forwarded service that lacks the route's scope", async () => {
    const asEnvoy = createMtlsFetch(identity("envoy-upstream"));
    const response = await asEnvoy(`${tlsUrl}/agents`, {
      method: "POST",
      headers: { [XFCC]: `URI=${serviceUri("vault")}` },
    });
    expect(response.status).toBe(401);
  });

  it("ignores a forged identity header on the plain port", async () => {
    const response = await fetch(`${plainUrl}/agents`, {
      method: "POST",
      headers: { [XFCC]: `URI=${serviceUri("identity")}` },
    });
    expect(response.status).toBe(401);
  });

  it("drops a genuine Custos service connecting to the TLS port directly, bypassing Envoy", async () => {
    const asIdentity = createMtlsFetch(identity("identity"));
    await expect(
      asIdentity(`${tlsUrl}/agents`, {
        method: "POST",
        headers: { [XFCC]: `URI=${serviceUri("identity")}` },
      }),
    ).rejects.toThrow();
  });

  it.each(["expired", "wrongca", "selfsigned"])(
    "refuses a %s client certificate at the TLS handshake",
    async (name) => {
      const bad = createMtlsFetch({
        cert: readFileSync(join(dir, `${name}.crt`), "utf8"),
        key: readFileSync(join(dir, `${name}.key`), "utf8"),
        ca: identity("identity").ca,
      });
      await expect(bad(`${tlsUrl}/agents`, { method: "POST" })).rejects.toThrow();
    },
  );

  it("refuses a client with no certificate", async () => {
    await expect(fetch(`${tlsUrl}/agents`, { method: "POST" })).rejects.toThrow();
  });
});

describe("createMtlsFetch", () => {
  it("refuses a non-https URL, so a misconfiguration can't go unauthenticated", async () => {
    const mtlsFetch = createMtlsFetch(identity("vault"));
    await expect(mtlsFetch(`${plainUrl}/agents`)).rejects.toThrow(/needs an https URL/);
  });

  it("refuses a non-string body rather than mangling it", async () => {
    const mtlsFetch = createMtlsFetch(identity("envoy-upstream"));
    await expect(
      mtlsFetch(`${tlsUrl}/agents`, { method: "POST", body: new Uint8Array([1]) }),
    ).rejects.toThrow(/string bodies only/);
  });

  it("honours an abort signal", async () => {
    const mtlsFetch = createMtlsFetch(identity("envoy-upstream"));
    await expect(
      mtlsFetch(`${tlsUrl}/agents`, { method: "POST", signal: AbortSignal.abort() }),
    ).rejects.toThrow();
  });
});

describe("loadMtlsIdentity", () => {
  it("loads a service's own certificate when it carries the expected identity", () => {
    expect(
      loadMtlsIdentity(files("vault"), { now: NOW, expectedUri: serviceUri("vault") }).ok,
    ).toBe(true);
  });

  it("refuses another service's certificate", () => {
    const result = loadMtlsIdentity(files("vault"), {
      now: NOW,
      expectedUri: serviceUri("identity"),
    });
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/is not for spiffe/) });
  });

  it("refuses an expired certificate", () => {
    const result = loadMtlsIdentity(files("expired"), { now: NOW });
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/is not valid now/) });
  });

  it("refuses a certificate from another CA", () => {
    const result = loadMtlsIdentity(files("wrongca"), { now: NOW });
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/is not signed by/) });
  });

  it("refuses a key that doesn't belong to the certificate", () => {
    const result = loadMtlsIdentity(
      { ...files("vault"), keyFile: join(dir, "identity.key") },
      { now: NOW },
    );
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/is not the key for/) });
  });

  it("reports a missing file without throwing", () => {
    const result = loadMtlsIdentity(
      { ...files("vault"), certFile: join(dir, "nope.crt") },
      { now: NOW },
    );
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/cannot load mTLS files/) });
  });

  it("never puts key material in an error", () => {
    const result = loadMtlsIdentity(
      { ...files("vault"), keyFile: join(dir, "identity.key") },
      { now: NOW },
    );
    expect(JSON.stringify(result)).not.toContain("PRIVATE KEY");
  });
});

describe("resolveOutgoingServiceAuth", () => {
  const guard = {
    authenticator: {
      authenticate: async () => ({ ok: false as const, error: { reason: "UNKNOWN_KEY" as const } }),
    },
    lockout: { isLocked: () => false, recordFailure: () => {} },
  };
  const base = { service: "vault", scopes: ["audit:write"] as const, guard, now: new Date() };

  it("uses a valid client certificate for this service", async () => {
    const result = await resolveOutgoingServiceAuth({
      ...base,
      now: NOW,
      serviceKey: undefined,
      mtls: files("vault"),
    });
    expect(result.ok && "mtlsFetch" in result.value).toBe(true);
  });

  it("refuses another service's certificate", async () => {
    const result = await resolveOutgoingServiceAuth({
      ...base,
      now: NOW,
      serviceKey: undefined,
      mtls: files("identity"),
    });
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/is not for spiffe/) });
  });

  it("refuses both a key and a certificate", async () => {
    const result = await resolveOutgoingServiceAuth({
      ...base,
      serviceKey: "k",
      mtls: files("vault"),
    });
    expect(result).toEqual({
      ok: false,
      error: "set a service key or a client certificate, not both",
    });
  });

  it("refuses neither", async () => {
    const result = await resolveOutgoingServiceAuth({ ...base, serviceKey: undefined, mtls: {} });
    expect(result).toEqual({ ok: false, error: "set a service key or a client certificate" });
  });

  it("refuses a partial certificate setting", async () => {
    const result = await resolveOutgoingServiceAuth({
      ...base,
      serviceKey: undefined,
      mtls: { certFile: files("vault").certFile },
    });
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/needs all three/) });
  });

  it("checks a service key against the key table", async () => {
    const result = await resolveOutgoingServiceAuth({
      ...base,
      serviceKey: ["custos", "service", "0123456789abcdef", "A".repeat(43)].join("_"),
      mtls: {},
    });
    expect(result).toEqual({
      ok: false,
      error: expect.stringMatching(/service key rejected: UNKNOWN_KEY/),
    });
  });
});

describe("resolveEnvoyListener", () => {
  it("is off when nothing is set", () => {
    expect(
      resolveEnvoyListener({
        port: undefined,
        certFile: undefined,
        keyFile: undefined,
        caFile: undefined,
        now: NOW,
      }),
    ).toEqual({ ok: true, value: null });
  });

  it("builds a listener when everything is set", () => {
    const f = files("audit-server");
    const result = resolveEnvoyListener({ port: 4014, ...f, now: NOW });
    expect(result.ok && result.value?.port).toBe(4014);
  });

  it("refuses a partial setting", () => {
    const result = resolveEnvoyListener({
      port: 4014,
      certFile: undefined,
      keyFile: undefined,
      caFile: undefined,
      now: NOW,
    });
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/needs all/) });
  });

  it("refuses an unusable certificate", () => {
    const result = resolveEnvoyListener({ port: 4014, ...files("expired"), now: NOW });
    expect(result).toEqual({ ok: false, error: expect.stringMatching(/is not valid now/) });
  });
});

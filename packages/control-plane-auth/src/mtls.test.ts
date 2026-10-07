import { describe, expect, it } from "vitest";
import type { ControlPlaneAuthenticator } from "./authenticator.js";
import {
  authenticateForwardedService,
  ENVOY_PROXY_URI,
  parseForwardedClientCertUri,
  serviceUri,
  withForwardedServiceCertificates,
} from "./mtls.js";

const XFCC = "x-forwarded-client-cert";
const viaEnvoy = (header: unknown) => ({
  headers: { [XFCC]: header as string },
  tlsPeerUris: [ENVOY_PROXY_URI],
});

describe("parseForwardedClientCertUri", () => {
  it("reads the one URI from Envoy's SANITIZE_SET header", () => {
    expect(parseForwardedClientCertUri(`By=spiffe://x;Hash=abc;URI=${serviceUri("vault")}`)).toBe(
      serviceUri("vault"),
    );
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["not a string (repeated header)", ["URI=a", "URI=b"]],
    ["two elements", `URI=${serviceUri("vault")},URI=${serviceUri("identity")}`],
    ["two URIs in one element", `URI=${serviceUri("vault")};URI=${serviceUri("identity")}`],
    ["no URI", "Hash=abc"],
    ["empty URI", "URI="],
    ["oversized", `URI=${"a".repeat(5000)}`],
  ])("refuses %s", (_label, header) => {
    expect(parseForwardedClientCertUri(header)).toBeNull();
  });
});

describe("authenticateForwardedService", () => {
  it("maps a forwarded service certificate to that service's principal and scopes", () => {
    expect(authenticateForwardedService(viaEnvoy(`URI=${serviceUri("identity")}`))).toEqual({
      ok: true,
      value: {
        kind: "service",
        id: serviceUri("identity"),
        name: "identity",
        scopes: new Set(["status:allocate", "audit:write"]),
      },
    });
  });

  it("gives the vault only audit:write", () => {
    const result = authenticateForwardedService(viaEnvoy(`URI=${serviceUri("vault")}`));
    expect(result?.ok && [...result.value.scopes]).toEqual(["audit:write"]);
  });

  it("ignores the header entirely unless the connection's verified TLS peer is Envoy", () => {
    const forged = `URI=${serviceUri("identity")}`;
    expect(authenticateForwardedService({ headers: { [XFCC]: forged } })).toBeNull();
    expect(
      authenticateForwardedService({ headers: { [XFCC]: forged }, tlsPeerUris: [] }),
    ).toBeNull();
    // A genuine Custos service connecting directly is not Envoy.
    expect(
      authenticateForwardedService({
        headers: { [XFCC]: forged },
        tlsPeerUris: [serviceUri("vault")],
      }),
    ).toBeNull();
  });

  it("refuses a connection from Envoy with no usable forwarded certificate", () => {
    expect(authenticateForwardedService(viaEnvoy(undefined))).toEqual({
      ok: false,
      error: { reason: "BAD_FORWARDED_CERT" },
    });
  });

  it.each([
    ["an unknown service", serviceUri("attacker")],
    ["a non-service SPIFFE ID", ENVOY_PROXY_URI],
    ["another trust domain", "spiffe://evil.example/service/identity"],
    ["a service name with a path", `${serviceUri("identity")}/x`],
  ])("refuses %s", (_label, uri) => {
    expect(authenticateForwardedService(viaEnvoy(`URI=${uri}`))).toEqual({
      ok: false,
      error: { reason: "UNKNOWN_SERVICE" },
    });
  });
});

describe("withForwardedServiceCertificates", () => {
  const fallback: ControlPlaneAuthenticator = {
    authenticate: async () => ({ ok: false, error: { reason: "MISSING" } }),
  };
  const chained = withForwardedServiceCertificates(fallback);

  it("uses the forwarded certificate on a connection from Envoy", async () => {
    const result = await chained.authenticate(viaEnvoy(`URI=${serviceUri("vault")}`));
    expect(result.ok && result.value.name).toBe("vault");
  });

  it("falls back to the API-key path everywhere else, ignoring the header", async () => {
    const result = await chained.authenticate({
      headers: { [XFCC]: `URI=${serviceUri("identity")}` },
    });
    expect(result).toEqual({ ok: false, error: { reason: "MISSING" } });
  });

  it("does not fall back when Envoy's forwarded identity is bad", async () => {
    const result = await chained.authenticate(viaEnvoy("garbage"));
    expect(result).toEqual({ ok: false, error: { reason: "BAD_FORWARDED_CERT" } });
  });
});

import { err, ok, type Result } from "@custos/contracts";
import type {
  AuthenticationFailure,
  AuthenticationRequest,
  ControlPlaneAuthenticator,
  Principal,
} from "./authenticator.js";
import type { Scope } from "./scopes.js";

/** The SAN of Envoy's own client certificate towards the services (ADR 0009). */
export const ENVOY_PROXY_URI = "spiffe://custos.local/proxy/envoy";

const SERVICE_URI = /^spiffe:\/\/custos\.local\/service\/([a-z]+)$/;

/**
 * What each Custos service may do when it proves itself with a certificate,
 * matching the scopes `custos-admin dev-keys` gives its API key. Envoy's
 * listeners already restrict who may call which service; this is the
 * service's own check on top.
 */
export const SERVICE_IDENTITY_SCOPES: Readonly<Record<string, readonly Scope[]>> = {
  identity: ["status:allocate", "audit:write"],
  vault: ["audit:write"],
  revocation: ["audit:write"],
};

export function serviceUri(service: string): string {
  return `spiffe://custos.local/service/${service}`;
}

/**
 * Parses Envoy's `x-forwarded-client-cert` header, as set by
 * `forward_client_cert_details: SANITIZE_SET` with `uri: true`: one element,
 * `;`-separated `key=value` pairs, one of which is `URI=`. Strict: more than
 * one element (a comma), more than one URI, or no URI is refused rather
 * than guessed at.
 */
export function parseForwardedClientCertUri(header: unknown): string | null {
  if (typeof header !== "string" || header.length === 0 || header.length > 4096) return null;
  if (header.includes(",")) return null;
  const uris = header
    .split(";")
    .filter((pair) => pair.startsWith("URI="))
    .map((pair) => pair.slice("URI=".length));
  return uris.length === 1 && uris[0] ? uris[0] : null;
}

/**
 * Authenticates a Custos service from the certificate Envoy verified
 * (ADR 0009). Applies only to a connection whose own TLS peer is Envoy;
 * anything else is `null` ("not mine"), so the caller can fall back to API
 * keys. An identity header on any other connection is never read.
 */
export function authenticateForwardedService(
  request: AuthenticationRequest,
): Result<Principal, AuthenticationFailure> | null {
  if (!request.tlsPeerUris?.includes(ENVOY_PROXY_URI)) return null;

  const uri = parseForwardedClientCertUri(request.headers["x-forwarded-client-cert"]);
  if (uri === null) return err({ reason: "BAD_FORWARDED_CERT" });
  const service = SERVICE_URI.exec(uri)?.[1];
  const scopes = service === undefined ? undefined : SERVICE_IDENTITY_SCOPES[service];
  if (service === undefined || scopes === undefined) return err({ reason: "UNKNOWN_SERVICE" });
  return ok({ kind: "service", id: uri, name: service, scopes: new Set(scopes) });
}

/** Tries a certificate forwarded by Envoy first, then the given (API-key) authenticator. */
export function withForwardedServiceCertificates(
  fallback: ControlPlaneAuthenticator,
): ControlPlaneAuthenticator {
  return {
    async authenticate(request) {
      return authenticateForwardedService(request) ?? fallback.authenticate(request);
    },
  };
}

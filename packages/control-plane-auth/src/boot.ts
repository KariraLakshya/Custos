import { err, ok, type Result } from "@custos/contracts";
import { checkServiceKey, type ControlPlaneGuard } from "./guard.js";
import { createMtlsFetch } from "./mtls-fetch.js";
import {
  createEnvoyOnlyTlsListener,
  loadMtlsIdentity,
  type EnvoyOnlyTlsListener,
} from "./mtls-server.js";
import { serviceUri } from "./mtls.js";
import type { Scope } from "./scopes.js";

/** How a service authenticates its calls to other Custos services. */
export type OutgoingServiceAuth =
  { readonly serviceKey: string } | { readonly mtlsFetch: typeof fetch };

/**
 * Boot-time choice and check of a service's outgoing credential: exactly
 * one of an API key (ADR 0008) or a client certificate (ADR 0009). The key
 * is checked against the key table, the certificate against its files.
 * Either failure stops the boot. Messages name keys by id and files by
 * path, never secrets.
 */
export async function resolveOutgoingServiceAuth(options: {
  readonly service: string;
  readonly scopes: readonly Scope[];
  readonly serviceKey: string | undefined;
  readonly mtls: {
    readonly certFile?: string;
    readonly keyFile?: string;
    readonly caFile?: string;
  };
  readonly guard: ControlPlaneGuard;
  readonly now: Date;
}): Promise<Result<OutgoingServiceAuth, string>> {
  const { certFile, keyFile, caFile } = options.mtls;
  const anyMtls = certFile !== undefined || keyFile !== undefined || caFile !== undefined;
  if (options.serviceKey !== undefined && anyMtls) {
    return err("set a service key or a client certificate, not both");
  }
  if (options.serviceKey !== undefined) {
    const checked = await checkServiceKey({
      ...options.guard,
      token: options.serviceKey,
      scopes: options.scopes,
    });
    return checked.ok ? ok({ serviceKey: options.serviceKey }) : err(checked.error);
  }
  if (certFile === undefined || keyFile === undefined || caFile === undefined) {
    return err(
      anyMtls
        ? "a client certificate needs all three of its cert, key and CA files"
        : "set a service key or a client certificate",
    );
  }
  const identity = loadMtlsIdentity(
    { certFile, keyFile, caFile },
    { now: options.now, expectedUri: serviceUri(options.service) },
  );
  return identity.ok ? ok({ mtlsFetch: createMtlsFetch(identity.value) }) : err(identity.error);
}

/**
 * Boot-time setup of a service's Envoy-only TLS listener (ADR 0009): all of
 * port, certificate, key and CA, or none (no listener; API keys only).
 */
export function resolveEnvoyListener(options: {
  readonly port: number | undefined;
  readonly certFile: string | undefined;
  readonly keyFile: string | undefined;
  readonly caFile: string | undefined;
  readonly now: Date;
}): Result<{ readonly listener: EnvoyOnlyTlsListener; readonly port: number } | null, string> {
  const { port, certFile, keyFile, caFile } = options;
  const set = [port, certFile, keyFile, caFile].filter((value) => value !== undefined).length;
  if (set === 0) return ok(null);
  if (
    port === undefined ||
    certFile === undefined ||
    keyFile === undefined ||
    caFile === undefined
  ) {
    return err("an mTLS listener needs all of its port, cert, key and CA");
  }
  const identity = loadMtlsIdentity({ certFile, keyFile, caFile }, { now: options.now });
  if (!identity.ok) return err(identity.error);
  return ok({ listener: createEnvoyOnlyTlsListener(identity.value), port });
}

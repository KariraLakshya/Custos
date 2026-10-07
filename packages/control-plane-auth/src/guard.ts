import { err, ok, type Result } from "@custos/contracts";
import {
  createApiKeyAuthenticator,
  type ControlPlaneAuthenticator,
  type Principal,
} from "./authenticator.js";
import { createLockout, type Lockout } from "./lockout.js";
import { withForwardedServiceCertificates } from "./mtls.js";
import type { Scope } from "./scopes.js";
import type { ApiKeyLookup } from "./store.js";

/** What a service needs to guard its control-plane routes with `requireScope`. */
export interface ControlPlaneGuard {
  readonly authenticator: ControlPlaneAuthenticator;
  readonly lockout: Lockout;
}

export function createControlPlaneGuard(options: {
  readonly keys: ApiKeyLookup;
  readonly clock: { now(): Date };
}): ControlPlaneGuard {
  return {
    // A certificate Envoy forwarded counts only on a connection whose own
    // verified TLS peer is Envoy (ADR 0009); everything else is API keys.
    authenticator: withForwardedServiceCertificates(createApiKeyAuthenticator(options)),
    lockout: createLockout({ clock: options.clock }),
  };
}

/**
 * Boot-time check of the service key a service will present to another
 * (ADR 0008 §6: a service refuses to boot without one). Catches a missing,
 * revoked, expired or wrongly-scoped key at startup rather than as a stream
 * of 401s at runtime. The message never contains the key.
 */
export async function checkServiceKey(options: {
  readonly authenticator: ControlPlaneAuthenticator;
  readonly token: string;
  readonly scopes: readonly Scope[];
}): Promise<Result<Principal, string>> {
  const result = await options.authenticator.authenticate({
    headers: { authorization: `Bearer ${options.token}` },
  });
  if (!result.ok) {
    const id = result.error.keyId ? ` (key ${result.error.keyId})` : "";
    return err(`service key rejected: ${result.error.reason}${id}`);
  }
  const principal = result.value;
  if (principal.kind !== "service") return err(`key ${principal.id} is not a service key`);
  const missing = options.scopes.filter((scope) => !principal.scopes.has(scope));
  if (missing.length > 0) {
    return err(`service key ${principal.id} lacks scope ${missing.join(", ")}`);
  }
  return ok(principal);
}

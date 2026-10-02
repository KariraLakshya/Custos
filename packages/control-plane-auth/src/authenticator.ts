import { err, ok, type Result } from "@custos/contracts";
import { parseApiKey, secretMatchesHash } from "./api-key.js";
import { isScope, scopeAllowedFor, type PrincipalKind, type Scope } from "./scopes.js";
import type { ApiKeyLookup } from "./store.js";

/** Who made a control-plane call. Route handlers and audit see only this (ADR 0008 §1). */
export interface Principal {
  readonly kind: PrincipalKind;
  /** Stable and safe to log. */
  readonly id: string;
  readonly name: string;
  readonly scopes: ReadonlySet<Scope>;
}

/** Why authentication failed — for logs only, never for the response (ADR 0008 §3). */
export interface AuthenticationFailure {
  readonly reason:
    | "MISSING"
    | "MALFORMED"
    | "UNKNOWN_KEY"
    | "WRONG_SECRET"
    | "KIND_MISMATCH"
    | "EXPIRED"
    | "REVOKED";
  /** Present once the key id could be parsed; the secret never is. */
  readonly keyId?: string;
}

export interface AuthenticationRequest {
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

/**
 * One interface for every way of proving a control-plane identity. API keys
 * now; mTLS and SSO later, as further implementations (ADR 0008 §1, §9).
 * Returns a value, not a throw: this is a security path (CLAUDE.md §7).
 */
export interface ControlPlaneAuthenticator {
  authenticate(request: AuthenticationRequest): Promise<Result<Principal, AuthenticationFailure>>;
}

const BEARER = /^Bearer ([^\s]+)$/;

export function createApiKeyAuthenticator(options: {
  readonly keys: ApiKeyLookup;
  readonly clock: { now(): Date };
}): ControlPlaneAuthenticator {
  return {
    async authenticate(request) {
      const header = request.headers.authorization;
      if (header === undefined) return err({ reason: "MISSING" });
      // Arrays (a repeated header) and oversized values are refused outright.
      if (typeof header !== "string" || header.length > 200) return err({ reason: "MALFORMED" });
      const bearer = BEARER.exec(header);
      const parsed = bearer ? parseApiKey(bearer[1]!) : null;
      if (!parsed) return err({ reason: "MALFORMED" });

      const keyId = parsed.id;
      const row = await options.keys.findById(keyId);
      if (!row) return err({ reason: "UNKNOWN_KEY", keyId });
      if (!secretMatchesHash(parsed.secret, row.secretHash)) {
        return err({ reason: "WRONG_SECRET", keyId });
      }
      if (row.kind !== parsed.kind) return err({ reason: "KIND_MISMATCH", keyId });
      if (row.revokedAt !== null) return err({ reason: "REVOKED", keyId });
      if (row.expiresAt.getTime() <= options.clock.now().getTime()) {
        return err({ reason: "EXPIRED", keyId });
      }

      // Re-checked here, not only at creation: a row edited by hand can't
      // give an operator key a service-only scope.
      const scopes = new Set<Scope>();
      for (const scope of row.scopes) {
        if (isScope(scope) && scopeAllowedFor(row.kind, scope)) scopes.add(scope);
      }
      return ok({ kind: row.kind, id: row.id, name: row.name, scopes });
    },
  };
}

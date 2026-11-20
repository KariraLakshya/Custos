import { createHash, randomBytes } from "node:crypto";
import type { AuditEvent } from "@custos/audit-client";
import type { ApiKeyStore, Scope } from "@custos/control-plane-auth";
import * as oidc from "openid-client";
import { readOnly, scopesForGroups } from "./config.js";
import type {
  CompletedLogin,
  LoginFailure,
  LoginStatus,
  LoginTransactions,
} from "./transactions.js";

/** How long a dashboard sign-in's one-time code may be used (ADR 0022 §4: within a minute). */
export const LOGIN_CODE_TTL_MS = 60_000;

/** What the callback did: a terminal login's status, or where to send the browser. */
export type CallbackOutcome =
  | LoginStatus
  | { readonly state: "return"; readonly returnTo: string; readonly code: string }
  | { readonly state: "return-failed"; readonly returnTo: string; readonly reason: LoginFailure };

export type ReleaseFailure = "INVALID_LOGIN_CODE" | "PROVIDER_ERROR";

export type ReleaseOutcome =
  | {
      readonly ok: true;
      readonly login: CompletedLogin & { readonly scopes: readonly Scope[] };
    }
  | { readonly ok: false; readonly reason: ReleaseFailure };

export interface OperatorSso {
  /** Whether `returnTo` is, character for character, one of `SSO_RETURN_URLS`. */
  allowsReturnTo(returnTo: string): boolean;
  /**
   * Begins a login: the URL to open in a browser, and the id to poll.
   * With `returnTo` (already checked with `allowsReturnTo`), a dashboard
   * login: read-only, finished by a one-time code instead of a poll.
   */
  start(options?: {
    readonly returnTo?: string;
  }): Promise<{ readonly loginId: string; readonly authorizationUrl: string } | null>;
  /**
   * Handles the provider's redirect back, given its query string. The URL
   * checked and sent as `redirect_uri` is the configured one, never the
   * request's own host, which a client controls. Where a dashboard login
   * returns to comes from the login itself, never from this query.
   */
  callback(query: string): Promise<CallbackOutcome>;
  /** The terminal's poll: pending, or the key once, or why it failed. */
  poll(loginId: string): LoginStatus;
  /** A dashboard login's key, once, for its one-time code. */
  release(loginId: string, code: string): Promise<ReleaseOutcome>;
}

const sha256 = (value: string): Buffer => createHash("sha256").update(value).digest();

/**
 * Operator SSO (ADR 0010): identity is a confidential OIDC relying party,
 * authorization code with PKCE, `state` and `nonce`. A verified ID token
 * becomes a short-lived operator API key named after the person, with
 * scopes from their groups. ID-token checks (signature against the
 * provider's JWKS, issuer, audience, nonce, expiry) are `openid-client`'s,
 * never hand-rolled.
 *
 * A dashboard login (ADR 0022 §4) is the same flow started with `returnTo`.
 * Its key holds only the group's read scopes, and is made only when the
 * dashboard presents the one-time code the browser brought back.
 */
export function createOperatorSso(options: {
  readonly config: oidc.Configuration;
  readonly redirectUrl: string;
  readonly groupScopes: ReadonlyMap<string, readonly Scope[]>;
  readonly returnUrls?: ReadonlySet<string>;
  readonly sessionMs: number;
  readonly keys: ApiKeyStore;
  readonly transactions: LoginTransactions;
  readonly clock: { now(): Date };
  readonly report?: (event: AuditEvent) => void;
  readonly log?: (fields: object, message: string) => void;
}): OperatorSso {
  const { config, transactions } = options;
  const returnUrls = options.returnUrls ?? new Set<string>();

  /** Makes the key and records the sign-in; `null` if the key store failed. */
  async function issueKey(
    name: string,
    scopes: readonly Scope[],
    rule: string,
  ): Promise<(CompletedLogin & { readonly scopes: readonly Scope[] }) | null> {
    const now = options.clock.now();
    const expiresAt = new Date(now.getTime() + options.sessionMs);
    const created = await options.keys.create({
      kind: "operator",
      name,
      scopes,
      expiresAt,
      now,
      createdVia: "sso",
    });
    if (!created.ok) return null;
    options.report?.({
      principal: { kind: "operator", id: created.id, name },
      action: "operator.login",
      dataCategories: [],
      policy: { rule, decision: "allow" },
    });
    return { operatorKey: created.token, name, expiresAt, scopes };
  }

  return {
    allowsReturnTo(returnTo) {
      return returnUrls.has(returnTo);
    },

    async start(startOptions = {}) {
      const { returnTo } = startOptions;
      if (returnTo !== undefined && !returnUrls.has(returnTo)) {
        throw new Error("operator SSO: returnTo was not checked against SSO_RETURN_URLS");
      }
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const pending = transactions.start({
        state: oidc.randomState(),
        nonce: oidc.randomNonce(),
        codeVerifier,
        ...(returnTo === undefined ? {} : { returnTo }),
      });
      if (pending === null) return null;
      const url = oidc.buildAuthorizationUrl(config, {
        redirect_uri: options.redirectUrl,
        scope: "openid email profile",
        response_type: "code",
        code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: "S256",
        state: pending.state,
        nonce: pending.nonce,
      });
      return { loginId: pending.loginId, authorizationUrl: url.href };
    },

    async callback(query) {
      const currentUrl = new URL(options.redirectUrl);
      currentUrl.search = query;
      const state = currentUrl.searchParams.get("state");
      const pending = state === null ? null : transactions.findByState(state);
      if (pending === null) return { state: "unknown" };
      const { returnTo } = pending;

      const fail = (reason: LoginFailure): CallbackOutcome => {
        transactions.finish(pending.loginId, { state: "failed", reason });
        return returnTo === undefined
          ? { state: "failed", reason }
          : { state: "return-failed", returnTo, reason };
      };

      let claims: oidc.IDToken | undefined;
      try {
        const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
          pkceCodeVerifier: pending.codeVerifier,
          expectedState: pending.state,
          expectedNonce: pending.nonce,
          idTokenExpected: true,
        });
        claims = tokens.claims();
      } catch (error) {
        // Never the token itself: the library's error code and message only.
        options.log?.(
          {
            loginId: pending.loginId,
            code: (error as { code?: unknown }).code,
            error: error instanceof Error ? error.message : String(error),
          },
          "operator SSO login refused",
        );
        return fail("TOKEN_REJECTED");
      }
      if (claims === undefined) return fail("TOKEN_REJECTED");

      const { scopes } = scopesForGroups(claims.groups, options.groupScopes);
      const name = typeof claims.email === "string" ? claims.email : claims.sub;
      if (scopes.length === 0) {
        options.log?.(
          { loginId: pending.loginId, sub: claims.sub },
          "operator SSO login: no mapped group",
        );
        return fail("NO_MAPPED_GROUP");
      }

      if (returnTo !== undefined) {
        // Read-only, whatever else the group may do. Fixed by how the login
        // started, never by anything a caller sends later.
        const readScopes = readOnly(scopes);
        if (readScopes.length === 0) {
          options.log?.(
            { loginId: pending.loginId, sub: claims.sub },
            "operator SSO dashboard login: no read scope",
          );
          return fail("NO_READ_SCOPE");
        }
        const code = randomBytes(32).toString("base64url");
        transactions.awaitRelease(pending.loginId, {
          codeHash: sha256(code),
          codeExpiresAt: options.clock.now().getTime() + LOGIN_CODE_TTL_MS,
          name,
          scopes: readScopes,
        });
        return { state: "return", returnTo, code };
      }

      const login = await issueKey(name, scopes, "operator-sso");
      if (login === null) return fail("PROVIDER_ERROR");
      const outcome: LoginStatus = {
        state: "complete",
        login: { operatorKey: login.operatorKey, name, expiresAt: login.expiresAt },
      };
      transactions.finish(pending.loginId, outcome);
      return outcome;
    },

    poll(loginId) {
      return transactions.take(loginId);
    },

    async release(loginId, code) {
      const accepted = transactions.release(loginId, sha256(code));
      if (accepted === null) {
        options.log?.({ loginId }, "operator SSO dashboard login: code refused");
        return { ok: false, reason: "INVALID_LOGIN_CODE" };
      }
      const login = await issueKey(accepted.name, accepted.scopes, "operator-sso-dashboard");
      return login === null ? { ok: false, reason: "PROVIDER_ERROR" } : { ok: true, login };
    },
  };
}

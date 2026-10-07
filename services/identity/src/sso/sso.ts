import type { AuditEvent } from "@custos/audit-client";
import type { ApiKeyStore, Scope } from "@custos/control-plane-auth";
import * as oidc from "openid-client";
import { scopesForGroups } from "./config.js";
import type { LoginStatus, LoginTransactions } from "./transactions.js";

export interface OperatorSso {
  /** Begins a login: the URL to open in a browser, and the id to poll. */
  start(): Promise<{ readonly loginId: string; readonly authorizationUrl: string } | null>;
  /**
   * Handles the provider's redirect back, given its query string. The URL
   * checked and sent as `redirect_uri` is the configured one, never the
   * request's own host, which a client controls.
   */
  callback(query: string): Promise<LoginStatus>;
  /** The terminal's poll: pending, or the key once, or why it failed. */
  poll(loginId: string): LoginStatus;
}

/**
 * Operator SSO (ADR 0010): identity is a confidential OIDC relying party,
 * authorization code with PKCE, `state` and `nonce`. A verified ID token
 * becomes a short-lived operator API key named after the person, with
 * scopes from their groups. ID-token checks (signature against the
 * provider's JWKS, issuer, audience, nonce, expiry) are `openid-client`'s,
 * never hand-rolled.
 */
export function createOperatorSso(options: {
  readonly config: oidc.Configuration;
  readonly redirectUrl: string;
  readonly groupScopes: ReadonlyMap<string, readonly Scope[]>;
  readonly sessionMs: number;
  readonly keys: ApiKeyStore;
  readonly transactions: LoginTransactions;
  readonly clock: { now(): Date };
  readonly report?: (event: AuditEvent) => void;
  readonly log?: (fields: object, message: string) => void;
}): OperatorSso {
  const { config, transactions } = options;

  return {
    async start() {
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const pending = transactions.start({
        state: oidc.randomState(),
        nonce: oidc.randomNonce(),
        codeVerifier,
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
        const outcome: LoginStatus = { state: "failed", reason: "TOKEN_REJECTED" };
        transactions.finish(pending.loginId, outcome);
        return outcome;
      }
      if (claims === undefined) {
        const outcome: LoginStatus = { state: "failed", reason: "TOKEN_REJECTED" };
        transactions.finish(pending.loginId, outcome);
        return outcome;
      }

      const { scopes } = scopesForGroups(claims.groups, options.groupScopes);
      const name = typeof claims.email === "string" ? claims.email : claims.sub;
      if (scopes.length === 0) {
        options.log?.(
          { loginId: pending.loginId, sub: claims.sub },
          "operator SSO login: no mapped group",
        );
        const outcome: LoginStatus = { state: "failed", reason: "NO_MAPPED_GROUP" };
        transactions.finish(pending.loginId, outcome);
        return outcome;
      }

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
      if (!created.ok) {
        const outcome: LoginStatus = { state: "failed", reason: "PROVIDER_ERROR" };
        transactions.finish(pending.loginId, outcome);
        return outcome;
      }
      options.report?.({
        principal: { kind: "operator", id: created.id, name },
        action: "operator.login",
        dataCategories: [],
        policy: { rule: "operator-sso", decision: "allow" },
      });
      const outcome: LoginStatus = {
        state: "complete",
        login: { operatorKey: created.token, name, expiresAt },
      };
      transactions.finish(pending.loginId, outcome);
      return outcome;
    },

    poll(loginId) {
      return transactions.take(loginId);
    },
  };
}

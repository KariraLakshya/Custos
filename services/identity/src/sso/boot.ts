import type { AuditEvent } from "@custos/audit-client";
import type { ApiKeyStore } from "@custos/control-plane-auth";
import { err, ok, type Result } from "@custos/core";
import * as oidc from "openid-client";
import type { Env } from "../env.js";
import { parseGroupScopes } from "./config.js";
import { createOperatorSso, type OperatorSso } from "./sso.js";
import { createLoginTransactions } from "./transactions.js";

type SsoFactory = (deps: {
  readonly report: (event: AuditEvent) => void;
  readonly log: (fields: object, message: string) => void;
}) => OperatorSso;

/**
 * The provider's configuration, by OIDC discovery. Always validates ID
 * token signatures against the provider's JWKS: `openid-client` otherwise
 * skips that for tokens from the token endpoint, relying on TLS (OIDC Core
 * 3.1.3.7). Custos checks them anyway, as ADR 0010 and the build plan
 * require, and because a local provider may be plain http, with no TLS to
 * rely on. Shared by boot and the tests, so they can't differ.
 */
export async function discoverProvider(options: {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly allowHttp: boolean;
}): Promise<oidc.Configuration> {
  return oidc.discovery(
    new URL(options.issuer),
    options.clientId,
    options.clientSecret,
    undefined,
    {
      execute: [
        oidc.enableNonRepudiationChecks,
        ...(options.allowHttp ? [oidc.allowInsecureRequests] : []),
      ],
    },
  );
}

/**
 * Operator SSO from configuration (ADR 0010), checked at boot: the group
 * mapping must parse, and the provider's discovery document must load, so
 * a misconfiguration stops the start rather than every later login.
 * `null` when SSO isn't configured.
 */
export async function createOperatorSsoFromEnv(
  env: Env,
  keys: ApiKeyStore,
): Promise<Result<SsoFactory | null, string>> {
  if (
    env.SSO_ISSUER === undefined ||
    env.SSO_CLIENT_ID === undefined ||
    env.SSO_CLIENT_SECRET === undefined ||
    env.SSO_REDIRECT_URL === undefined ||
    env.SSO_GROUP_SCOPES === undefined
  ) {
    return ok(null);
  }
  const groupScopes = parseGroupScopes(env.SSO_GROUP_SCOPES);
  if (!groupScopes.ok) return err(groupScopes.error);
  let config: oidc.Configuration;
  try {
    config = await discoverProvider({
      issuer: env.SSO_ISSUER,
      clientId: env.SSO_CLIENT_ID,
      clientSecret: env.SSO_CLIENT_SECRET,
      allowHttp: env.SSO_ALLOW_HTTP_ISSUER === "true",
    });
  } catch (error) {
    return err(
      `cannot load the SSO provider's configuration from ${env.SSO_ISSUER}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const clock = { now: () => new Date() };
  const transactions = createLoginTransactions({ clock });
  const redirectUrl = env.SSO_REDIRECT_URL;
  const sessionMs = env.SSO_SESSION_HOURS * 3_600_000;
  return ok(({ report, log }) =>
    createOperatorSso({
      config,
      redirectUrl,
      groupScopes: groupScopes.value,
      sessionMs,
      keys,
      transactions,
      clock,
      report,
      log,
    }),
  );
}

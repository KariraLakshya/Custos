import { baseEnvSchema, loadEnv } from "@custos/config";
import { parseApiKey } from "@custos/control-plane-auth";
import { z } from "zod";

const fieldsSchema = baseEnvSchema.extend({
  PORT: z.coerce.number().int().positive().default(4001),
  // Domain each agent's did:web document is published under, e.g.
  // did:web:{domain}:agents:{id}.
  IDENTITY_DID_DOMAIN: z.string().min(1).default("localhost:4001"),
  DATABASE_URL: z.string().min(1).default("postgres://custos:custos@localhost:5433/custos"),
  // Registration reserves the agent's status list bit here before issuing
  // its credential, and fails closed if this service is unreachable — an
  // un-revokable agent is worse than a failed registration.
  REVOCATION_URL: z.string().min(1).default("http://localhost:4003"),
  // Its control-plane writes are reported here (ADR 0008 §7).
  AUDIT_URL: z.string().min(1).default("http://localhost:4004"),
  // Its calls to other Custos services authenticate with exactly one of:
  // this API key (ADR 0008), or a client certificate through Envoy
  // (ADR 0009: IDENTITY_MTLS_CERT + IDENTITY_MTLS_KEY + MTLS_CA; then the target
  // URLs are Envoy's https:// listeners). Checked at boot.
  IDENTITY_SERVICE_KEY: z
    .string()
    .refine((value) => parseApiKey(value)?.kind === "service", "must be a custos_service_ key")
    .optional(),
  IDENTITY_MTLS_CERT: z.string().min(1).optional(),
  IDENTITY_MTLS_KEY: z.string().min(1).optional(),
  MTLS_CA: z.string().min(1).optional(),
  // Where the issuer key that signs every agent credential lives. Credentials
  // outlive the process, so either way the key survives restarts (ADR 0007
  // decision 4). "local": derived from IDENTITY_ISSUER_SEED, dev only. "kms":
  // an AWS KMS Ed25519 key, IDENTITY_ISSUER_KMS_KEY_ID; region and
  // credentials come from the standard AWS configuration.
  IDENTITY_KEY_PROVIDER: z.enum(["local", "kms"]).default("local"),
  // 32-byte seed (64 hex chars). Required for "local", with no default: the
  // service refuses to boot rather than fall back to a known or ephemeral key.
  IDENTITY_ISSUER_SEED: z
    .string()
    .regex(/^[0-9a-f]{64}$/i, "must be 64 hex characters (32 bytes)")
    .optional(),
  // Key id or ARN of an ECC_NIST_EDWARDS25519 / SIGN_VERIFY key. Required for "kms".
  IDENTITY_ISSUER_KMS_KEY_ID: z.string().min(1).optional(),
  // Freshness window for a registration proof of possession: |now − iat|.
  // Explicit configuration, never an accident (CLAUDE.md section 3).
  IDENTITY_REGISTRATION_PROOF_MAX_SKEW_SECONDS: z.coerce.number().int().positive().default(60),
  // Operator SSO (ADR 0010), optional: all of issuer, client, secret,
  // redirect URL and group mapping, or none (no /operator/* routes).
  SSO_ISSUER: z.string().url().optional(),
  SSO_CLIENT_ID: z.string().min(1).optional(),
  SSO_CLIENT_SECRET: z.string().min(1).optional(),
  // This service's public callback URL, registered with the provider.
  SSO_REDIRECT_URL: z.string().url().optional(),
  // JSON: company group -> operator scopes, e.g. {"custos-admins":["agents:register"]}.
  SSO_GROUP_SCOPES: z.string().min(1).optional(),
  // Lifetime of the operator key a login issues. Capped: SSO sessions are short.
  SSO_SESSION_HOURS: z.coerce.number().int().min(1).max(24).default(8),
  // Plain-http issuer, for a local development provider only.
  SSO_ALLOW_HTTP_ISSUER: z.enum(["true", "false"]).default("false"),
});

// The provider selects which key setting is required; a missing one is a
// boot failure, never a silent fallback to the other provider.
export const envSchema = fieldsSchema.superRefine((env, ctx) => {
  const sso = [
    env.SSO_ISSUER,
    env.SSO_CLIENT_ID,
    env.SSO_CLIENT_SECRET,
    env.SSO_REDIRECT_URL,
    env.SSO_GROUP_SCOPES,
  ];
  if (sso.some((value) => value !== undefined) && sso.some((value) => value === undefined)) {
    ctx.addIssue({
      code: "custom",
      path: ["SSO_ISSUER"],
      message:
        "SSO needs all of SSO_ISSUER, SSO_CLIENT_ID, SSO_CLIENT_SECRET, SSO_REDIRECT_URL, SSO_GROUP_SCOPES",
    });
  }
  if (env.SSO_ISSUER?.startsWith("http:")) {
    const host = new URL(env.SSO_ISSUER).hostname;
    const local = host === "localhost" || host === "127.0.0.1";
    if (!local || env.SSO_ALLOW_HTTP_ISSUER !== "true") {
      ctx.addIssue({
        code: "custom",
        path: ["SSO_ISSUER"],
        message: "an http:// issuer is allowed only for localhost, with SSO_ALLOW_HTTP_ISSUER=true",
      });
    }
  }
  if (env.IDENTITY_SERVICE_KEY === undefined && env.IDENTITY_MTLS_CERT === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["IDENTITY_SERVICE_KEY"],
      message: "set IDENTITY_SERVICE_KEY, or IDENTITY_MTLS_CERT + IDENTITY_MTLS_KEY + MTLS_CA",
    });
  }
  if (env.IDENTITY_SERVICE_KEY !== undefined && env.IDENTITY_MTLS_CERT !== undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["IDENTITY_MTLS_CERT"],
      message: "set IDENTITY_SERVICE_KEY or IDENTITY_MTLS_CERT, not both",
    });
  }
  if (env.IDENTITY_KEY_PROVIDER === "local" && env.IDENTITY_ISSUER_SEED === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["IDENTITY_ISSUER_SEED"],
      message: "required when IDENTITY_KEY_PROVIDER is local",
    });
  }
  if (env.IDENTITY_KEY_PROVIDER === "kms" && env.IDENTITY_ISSUER_KMS_KEY_ID === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["IDENTITY_ISSUER_KMS_KEY_ID"],
      message: "required when IDENTITY_KEY_PROVIDER is kms",
    });
  }
});

export type Env = z.infer<typeof envSchema>;

export function loadIdentityEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

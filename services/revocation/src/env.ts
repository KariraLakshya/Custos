import { baseEnvSchema, loadEnv } from "@custos/config";
import { parseApiKey } from "@custos/control-plane-auth";
import { z } from "zod";

const fieldsSchema = baseEnvSchema.extend({
  PORT: z.coerce.number().int().positive().default(4003),
  DATABASE_URL: z.string().min(1).default("postgres://custos:custos@localhost:5433/custos"),
  // Domain this service's own did:web document is published under. It signs
  // every tombstone and the status list credential, so subscribers resolve
  // this DID to get the key they verify against. Includes the port, since
  // the identity service publishes under the same host on a different one.
  REVOCATION_DID_DOMAIN: z.string().min(1).default("localhost:4003"),
  // Where the key that signs every tombstone and the status list credential
  // lives (ADR 0016). "local": derived from REVOCATION_SIGNING_SEED, dev only.
  // "kms": an AWS KMS Ed25519 key, REVOCATION_SIGNING_KMS_KEY_ID; region and
  // credentials from the standard AWS configuration. The publisher signs as
  // this service, so in production it uses the same KMS key.
  REVOCATION_KEY_PROVIDER: z.enum(["local", "kms"]).default("local"),
  // 32-byte seed (64 hex chars). Required when local, with no default: the
  // service refuses to boot rather than fall back to a known or ephemeral key
  // (ADR 0012). Keep the same seed across restarts, or subscribers must
  // re-verify everything.
  REVOCATION_SIGNING_SEED: z
    .string()
    .regex(/^[0-9a-f]{64}$/i, "must be 64 hex characters (32 bytes)")
    .optional(),
  REVOCATION_SIGNING_KMS_KEY_ID: z.string().min(1).optional(),
  // Base URLs a signed tombstone is pushed to on revocation — the "registered
  // tool adapters" of the build plan, reached through the vault that holds
  // their connectors. Comma-separated; empty disables broadcast entirely.
  REVOCATION_SUBSCRIBER_URLS: z
    .string()
    .default("http://localhost:4002")
    .transform((value) =>
      value
        .split(",")
        .map((url) => url.trim())
        .filter((url) => url.length > 0),
    ),
  // Published in the status list credential's `ttl`: how long a third-party
  // verifier may cache the list before refetching. CLAUDE.md section 3
  // requires this bound be explicit configuration, never an accident.
  REVOCATION_STATUS_TTL_MS: z.coerce.number().int().positive().default(30_000),
  // How long a signed status list is served again while its contents are
  // unchanged (ADR 0016), so anonymous requests cannot each cost a signature.
  // A revocation is signed at once regardless. Keep it well below the vault's
  // REVOCATION_MAX_STALENESS_MS, since the list's validFrom lags by up to this.
  REVOCATION_STATUS_REUSE_MS: z.coerce.number().int().positive().default(5_000),
  // The published status list this service merges into its own state (ADR 0014).
  // Unset: the feature is off and nothing changes. Set: the window and the poll
  // interval are required (no defaults), because while it is on this service
  // stops answering "who is revoked" once the newest verified list is past its
  // window.
  REVOCATION_PUBLISHED_LIST_URL: z.string().url().optional(),
  REVOCATION_PUBLISHED_MAX_AGE_SECONDS: z.coerce.number().int().positive().optional(),
  REVOCATION_PUBLISHED_POLL_SECONDS: z.coerce.number().int().positive().optional(),
  // How far the publisher's clock may be ahead of this one.
  REVOCATION_PUBLISHED_MAX_CLOCK_SKEW_SECONDS: z.coerce.number().int().nonnegative().default(5),
  // Revocations and status allocations are reported here (ADR 0008 §7).
  AUDIT_URL: z.string().min(1).default("http://localhost:4004"),
  // Its calls to other Custos services authenticate with exactly one of:
  // this API key (ADR 0008), or a client certificate through Envoy
  // (ADR 0009: REVOCATION_MTLS_CERT + REVOCATION_MTLS_KEY + MTLS_CA; then the target
  // URLs are Envoy's https:// listeners). Checked at boot.
  REVOCATION_SERVICE_KEY: z
    .string()
    .refine((value) => parseApiKey(value)?.kind === "service", "must be a custos_service_ key")
    .optional(),
  REVOCATION_MTLS_CERT: z.string().min(1).optional(),
  REVOCATION_MTLS_KEY: z.string().min(1).optional(),
  MTLS_CA: z.string().min(1).optional(),
  // Optional Envoy-only TLS listener (ADR 0009): all three, plus MTLS_CA,
  // or none. Envoy forwards callers' certificates to it (dev port 4013).
  REVOCATION_MTLS_PORT: z.coerce.number().int().positive().optional(),
  REVOCATION_MTLS_SERVER_CERT: z.string().min(1).optional(),
  REVOCATION_MTLS_SERVER_KEY: z.string().min(1).optional(),
});

export const envSchema = fieldsSchema.superRefine((env, ctx) => {
  if (env.REVOCATION_KEY_PROVIDER === "local" && env.REVOCATION_SIGNING_SEED === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["REVOCATION_SIGNING_SEED"],
      message: "required when REVOCATION_KEY_PROVIDER is local",
    });
  }
  if (env.REVOCATION_KEY_PROVIDER === "kms" && env.REVOCATION_SIGNING_KMS_KEY_ID === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["REVOCATION_SIGNING_KMS_KEY_ID"],
      message: "required when REVOCATION_KEY_PROVIDER is kms",
    });
  }
  if (
    env.REVOCATION_PUBLISHED_MAX_AGE_SECONDS !== undefined &&
    env.REVOCATION_PUBLISHED_POLL_SECONDS !== undefined &&
    env.REVOCATION_PUBLISHED_POLL_SECONDS >= env.REVOCATION_PUBLISHED_MAX_AGE_SECONDS
  ) {
    // A list is only fresh for the window; polling no faster than that would keep
    // the gate closed most of the time.
    ctx.addIssue({
      code: "custom",
      path: ["REVOCATION_PUBLISHED_POLL_SECONDS"],
      message: "must be shorter than REVOCATION_PUBLISHED_MAX_AGE_SECONDS",
    });
  }
  if (env.REVOCATION_PUBLISHED_LIST_URL !== undefined) {
    for (const name of [
      "REVOCATION_PUBLISHED_MAX_AGE_SECONDS",
      "REVOCATION_PUBLISHED_POLL_SECONDS",
    ] as const) {
      if (env[name] === undefined) {
        ctx.addIssue({
          code: "custom",
          path: [name],
          message: `required when REVOCATION_PUBLISHED_LIST_URL is set`,
        });
      }
    }
  }
  if (env.REVOCATION_SERVICE_KEY === undefined && env.REVOCATION_MTLS_CERT === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["REVOCATION_SERVICE_KEY"],
      message:
        "set REVOCATION_SERVICE_KEY, or REVOCATION_MTLS_CERT + REVOCATION_MTLS_KEY + MTLS_CA",
    });
  }
  if (env.REVOCATION_SERVICE_KEY !== undefined && env.REVOCATION_MTLS_CERT !== undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["REVOCATION_MTLS_CERT"],
      message: "set REVOCATION_SERVICE_KEY or REVOCATION_MTLS_CERT, not both",
    });
  }
});

export type Env = z.infer<typeof envSchema>;

export function loadRevocationEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

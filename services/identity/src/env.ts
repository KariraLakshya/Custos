import { baseEnvSchema, loadEnv } from "@custos/config";
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
});

// The provider selects which key setting is required; a missing one is a
// boot failure, never a silent fallback to the other provider.
export const envSchema = fieldsSchema.superRefine((env, ctx) => {
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

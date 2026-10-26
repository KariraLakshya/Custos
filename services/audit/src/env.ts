import { baseEnvSchema, loadEnv } from "@custos/config";
import { z } from "zod";

const fieldsSchema = baseEnvSchema.extend({
  PORT: z.coerce.number().int().positive().default(4004),
  DATABASE_URL: z.string().min(1).default("postgres://custos:custos@localhost:5433/custos"),
  // Domain this service's own did:web document is published under. It signs
  // every audit record, so a pulled record is verified against this DID —
  // independent of whatever service originally reported the event.
  AUDIT_DID_DOMAIN: z.string().min(1).default("localhost:4004"),
  // The key that signs the ledger's seals (ADR 0017 §3), mirroring
  // revocation's (ADR 0016). "local": derived from AUDIT_SIGNING_SEED, dev
  // only, required with no default, kept across restarts. "kms": an AWS KMS
  // Ed25519 key, AUDIT_SIGNING_KMS_KEY_ID.
  AUDIT_KEY_PROVIDER: z.enum(["local", "kms"]).default("local"),
  AUDIT_SIGNING_SEED: z
    .string()
    .regex(/^[0-9a-f]{64}$/i, "must be 64 hex characters (32 bytes)")
    .optional(),
  AUDIT_SIGNING_KMS_KEY_ID: z.string().min(1).optional(),
  // How often the head of the ledger is sealed, when it has moved (ADR 0017
  // §2). Entries newer than the last seal are not sealed yet.
  AUDIT_SEAL_INTERVAL_MS: z.coerce.number().int().positive().default(10_000),
  // Optional Envoy-only TLS listener (ADR 0009): all three, plus MTLS_CA,
  // or none. Envoy forwards callers' certificates to it (dev port 4014).
  AUDIT_MTLS_PORT: z.coerce.number().int().positive().optional(),
  AUDIT_MTLS_SERVER_CERT: z.string().min(1).optional(),
  AUDIT_MTLS_SERVER_KEY: z.string().min(1).optional(),
  MTLS_CA: z.string().min(1).optional(),
});

export const envSchema = fieldsSchema.superRefine((env, ctx) => {
  if (env.AUDIT_KEY_PROVIDER === "local" && env.AUDIT_SIGNING_SEED === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["AUDIT_SIGNING_SEED"],
      message: "required when AUDIT_KEY_PROVIDER is local",
    });
  }
  if (env.AUDIT_KEY_PROVIDER === "kms" && env.AUDIT_SIGNING_KMS_KEY_ID === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["AUDIT_SIGNING_KMS_KEY_ID"],
      message: "required when AUDIT_KEY_PROVIDER is kms",
    });
  }
});

export type Env = z.infer<typeof envSchema>;

export function loadAuditEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

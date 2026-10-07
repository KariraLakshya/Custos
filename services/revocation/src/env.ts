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

import { baseEnvSchema, loadEnv } from "@custos/config";
import { parseApiKey } from "@custos/control-plane-auth";
import { z } from "zod";

const fieldsSchema = baseEnvSchema.extend({
  PORT: z.coerce.number().int().positive().default(4002),
  DATABASE_URL: z.string().min(1).default("postgres://custos:custos@localhost:5433/custos"),
  // 32-byte key (64 hex chars) for the local SecretCipher encrypting stored
  // tool credentials at rest — see docs/adr/0004-vault-credential-encryption.md.
  // No default: refuses to boot rather than fall back to a known key.
  VAULT_MASTER_KEY: z.string().regex(/^[0-9a-f]{64}$/i, "must be 64 hex characters (32 bytes)"),
  REVOCATION_URL: z.string().min(1).default("http://localhost:4003"),
  // DID of the revocation service, resolved once to get the key every pushed
  // tombstone is verified against. Must match REVOCATION_DID_DOMAIN there.
  REVOCATION_ISSUER_DID: z.string().min(1).default("did:web:localhost%3A4003"),
  // DID of the identity service, the only issuer whose agent credentials this
  // vault accepts (ADR 0007). Must match IDENTITY_DID_DOMAIN there.
  VAULT_TRUSTED_ISSUER_DID: z.string().min(1).default("did:web:localhost%3A4001"),
  // This vault's public base URL as agents reach it; token-request proofs
  // must be addressed to <VAULT_PUBLIC_URL>/tokens (ADR 0007).
  VAULT_PUBLIC_URL: z.string().url().default("http://localhost:4002"),
  // Freshness window for a token-request proof: |now - iat|. Explicit
  // configuration, never an accident (CLAUDE.md section 3).
  VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS: z.coerce.number().int().positive().default(60),
  // Bounded staleness (CLAUDE.md section 3): if no resync has succeeded
  // within this window the vault denies calls rather than trusting a stale
  // allow list. Explicit configuration, never an accident.
  REVOCATION_MAX_STALENESS_MS: z.coerce.number().int().positive().default(30_000),
  REVOCATION_RESYNC_INTERVAL_MS: z.coerce.number().int().positive().default(10_000),
  AUDIT_URL: z.string().min(1).default("http://localhost:4004"),
  // Its calls to other Custos services authenticate with exactly one of:
  // this API key (ADR 0008), or a client certificate through Envoy
  // (ADR 0009: VAULT_MTLS_CERT + VAULT_MTLS_KEY + MTLS_CA; then the target
  // URLs are Envoy's https:// listeners). Checked at boot.
  VAULT_SERVICE_KEY: z
    .string()
    .refine((value) => parseApiKey(value)?.kind === "service", "must be a custos_service_ key")
    .optional(),
  VAULT_MTLS_CERT: z.string().min(1).optional(),
  VAULT_MTLS_KEY: z.string().min(1).optional(),
  MTLS_CA: z.string().min(1).optional(),
});

export const envSchema = fieldsSchema.superRefine((env, ctx) => {
  if (env.VAULT_SERVICE_KEY === undefined && env.VAULT_MTLS_CERT === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["VAULT_SERVICE_KEY"],
      message: "set VAULT_SERVICE_KEY, or VAULT_MTLS_CERT + VAULT_MTLS_KEY + MTLS_CA",
    });
  }
  if (env.VAULT_SERVICE_KEY !== undefined && env.VAULT_MTLS_CERT !== undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["VAULT_MTLS_CERT"],
      message: "set VAULT_SERVICE_KEY or VAULT_MTLS_CERT, not both",
    });
  }
});

export type Env = z.infer<typeof envSchema>;

export function loadVaultEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

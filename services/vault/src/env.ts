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
  // At most 5 minutes; it is also a delegation chain's clock skew, which
  // `custos audit-log` re-verifies under this upper bound.
  VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS: z.coerce.number().int().positive().max(300).default(60),
  // Delegation chains (ADR 0020): most hand-offs in one chain, longest a
  // hand-off may live, most bytes of hand-offs and credentials together.
  // A chain over any of them is refused; there is no way to switch them off.
  DELEGATION_MAX_LINKS: z.coerce.number().int().positive().max(15).default(3),
  // At most a day: `custos audit-log` re-verifies chains under these upper bounds.
  DELEGATION_MAX_LIFETIME_SECONDS: z.coerce.number().int().positive().max(86_400).default(3600),
  DELEGATION_MAX_BYTES: z.coerce.number().int().positive().max(262_144).default(16_384),
  // Bounded staleness (CLAUDE.md section 3): if no resync has succeeded
  // within this window the vault denies calls rather than trusting a stale
  // allow list. Explicit configuration, never an accident.
  REVOCATION_MAX_STALENESS_MS: z.coerce.number().int().positive().default(30_000),
  REVOCATION_RESYNC_INTERVAL_MS: z.coerce.number().int().positive().default(10_000),
  // How far the revocation service's clock and this one may differ. A resync
  // takes its freshness from the status list's signed time, so the rule
  // depends on the two clocks agreeing (ADR 0013). Explicit config.
  REVOCATION_LIST_MAX_CLOCK_SKEW_SECONDS: z.coerce.number().int().nonnegative().default(5),
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

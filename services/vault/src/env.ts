import { baseEnvSchema, loadEnv } from "@custos/config";
import { z } from "zod";

export const envSchema = baseEnvSchema.extend({
  PORT: z.coerce.number().int().positive().default(4002),
  DATABASE_URL: z.string().min(1).default("postgres://custos:custos@localhost:5433/custos"),
  // 32-byte key (64 hex chars) for the local SecretCipher encrypting stored
  // tool credentials at rest — see docs/adr/0004-vault-credential-encryption.md.
  // No default: refuses to boot rather than fall back to a known key.
  VAULT_MASTER_KEY: z.string().regex(/^[0-9a-f]{64}$/i, "must be 64 hex characters (32 bytes)"),
});

export type Env = z.infer<typeof envSchema>;

export function loadVaultEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

import { baseEnvSchema, loadEnv } from "@custos/config";
import { z } from "zod";

export const envSchema = baseEnvSchema.extend({
  PORT: z.coerce.number().int().positive().default(4001),
  // Domain this service's did:web document is published under. Phase 0 only:
  // once agents get their own DIDs (Phase 1), this becomes per-agent, not
  // service-wide.
  IDENTITY_DID_DOMAIN: z.string().min(1).default("localhost:4001"),
});

export type Env = z.infer<typeof envSchema>;

export function loadIdentityEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

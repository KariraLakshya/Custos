import { baseEnvSchema, loadEnv } from "@custos/config";
import { z } from "zod";

export const envSchema = baseEnvSchema.extend({
  PORT: z.coerce.number().int().positive().default(4001),
});

export type Env = z.infer<typeof envSchema>;

export function loadIdentityEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

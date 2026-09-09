import { baseEnvSchema, loadEnv } from "@custos/config";
import { z } from "zod";

export const envSchema = baseEnvSchema.extend({
  PORT: z.coerce.number().int().positive().default(4001),
  // Domain each agent's did:web document is published under, e.g.
  // did:web:{domain}:agents:{id}.
  IDENTITY_DID_DOMAIN: z.string().min(1).default("localhost:4001"),
  DATABASE_URL: z.string().min(1).default("postgres://custos:custos@localhost:5433/custos"),
  // Registration reserves the agent's status list bit here before issuing
  // its credential, and fails closed if this service is unreachable — an
  // un-revokable agent is worse than a failed registration.
  REVOCATION_URL: z.string().min(1).default("http://localhost:4003"),
});

export type Env = z.infer<typeof envSchema>;

export function loadIdentityEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

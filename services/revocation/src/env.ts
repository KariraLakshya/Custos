import { baseEnvSchema, loadEnv } from "@custos/config";
import { z } from "zod";

export const envSchema = baseEnvSchema.extend({
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
});

export type Env = z.infer<typeof envSchema>;

export function loadRevocationEnv(source?: Record<string, string | undefined>): Env {
  return loadEnv(envSchema, source);
}

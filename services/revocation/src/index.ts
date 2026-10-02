import {
  checkServiceKey,
  createApiKeyStore,
  createControlPlaneGuard,
} from "@custos/control-plane-auth";
import { createDb } from "./db/client.js";
import { loadRevocationEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadRevocationEnv();
const db = createDb(env.DATABASE_URL);

const controlPlaneAuth = createControlPlaneGuard({
  keys: createApiKeyStore(db),
  clock: { now: () => new Date() },
});

// Refuse to boot on a service key that can't do its job (ADR 0008 §6).
const serviceKeyCheck = await checkServiceKey({
  ...controlPlaneAuth,
  token: env.REVOCATION_SERVICE_KEY,
  scopes: ["audit:write"],
});
if (!serviceKeyCheck.ok) {
  throw new Error(`REVOCATION_SERVICE_KEY: ${serviceKeyCheck.error}`);
}

const app = await buildServer({
  db,
  controlPlaneAuth,
  serviceKey: env.REVOCATION_SERVICE_KEY,
  auditUrl: env.AUDIT_URL,
  didDomain: env.REVOCATION_DID_DOMAIN,
  subscriberUrls: env.REVOCATION_SUBSCRIBER_URLS,
  statusTtlMs: env.REVOCATION_STATUS_TTL_MS,
});

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

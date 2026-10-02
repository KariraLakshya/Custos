import { createApiKeyStore, createControlPlaneGuard } from "@custos/control-plane-auth";
import { createDb } from "./db/client.js";
import { loadRevocationEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadRevocationEnv();
const db = createDb(env.DATABASE_URL);

const controlPlaneAuth = createControlPlaneGuard({
  keys: createApiKeyStore(db),
  clock: { now: () => new Date() },
});

const app = await buildServer({
  db,
  controlPlaneAuth,
  didDomain: env.REVOCATION_DID_DOMAIN,
  subscriberUrls: env.REVOCATION_SUBSCRIBER_URLS,
  statusTtlMs: env.REVOCATION_STATUS_TTL_MS,
});

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

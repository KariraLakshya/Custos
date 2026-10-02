import { createApiKeyStore, createControlPlaneGuard } from "@custos/control-plane-auth";
import { createDb } from "./db/client.js";
import { loadAuditEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadAuditEnv();
const db = createDb(env.DATABASE_URL);

const controlPlaneAuth = createControlPlaneGuard({
  keys: createApiKeyStore(db),
  clock: { now: () => new Date() },
});

const app = await buildServer({ db, controlPlaneAuth, didDomain: env.AUDIT_DID_DOMAIN });

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

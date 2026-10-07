import {
  createApiKeyStore,
  createControlPlaneGuard,
  resolveEnvoyListener,
} from "@custos/control-plane-auth";
import { createDb } from "./db/client.js";
import { loadAuditEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadAuditEnv();
const db = createDb(env.DATABASE_URL);

const controlPlaneAuth = createControlPlaneGuard({
  keys: createApiKeyStore(db),
  clock: { now: () => new Date() },
});

// The optional Envoy-only TLS listener (ADR 0009).
const tls = resolveEnvoyListener({
  port: env.AUDIT_MTLS_PORT,
  certFile: env.AUDIT_MTLS_SERVER_CERT,
  keyFile: env.AUDIT_MTLS_SERVER_KEY,
  caFile: env.MTLS_CA,
  now: new Date(),
});
if (!tls.ok) {
  throw new Error(`audit mTLS listener: ${tls.error}`);
}

const app = await buildServer({
  db,
  controlPlaneAuth,
  didDomain: env.AUDIT_DID_DOMAIN,
  ...(tls.value ? { serverFactory: tls.value.listener.serverFactory } : {}),
});

try {
  await app.listen({ port: env.PORT, host: "0.0.0.0" });
  if (tls.value) await tls.value.listener.listen(tls.value.port, "0.0.0.0");
} catch (err: unknown) {
  app.log.error(err);
  process.exit(1);
}

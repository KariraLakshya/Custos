import {
  createApiKeyStore,
  createControlPlaneGuard,
  resolveEnvoyListener,
  resolveOutgoingServiceAuth,
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

// Exactly one of an API key or a client certificate, checked before
// serving (ADR 0008 §6, ADR 0009).
const outgoing = await resolveOutgoingServiceAuth({
  service: "revocation",
  scopes: ["audit:write"],
  serviceKey: env.REVOCATION_SERVICE_KEY,
  mtls: {
    certFile: env.REVOCATION_MTLS_CERT,
    keyFile: env.REVOCATION_MTLS_KEY,
    caFile: env.MTLS_CA,
  },
  guard: controlPlaneAuth,
  now: new Date(),
});
if (!outgoing.ok) {
  throw new Error(`revocation: ${outgoing.error}`);
}

// The optional Envoy-only TLS listener (ADR 0009).
const tls = resolveEnvoyListener({
  port: env.REVOCATION_MTLS_PORT,
  certFile: env.REVOCATION_MTLS_SERVER_CERT,
  keyFile: env.REVOCATION_MTLS_SERVER_KEY,
  caFile: env.MTLS_CA,
  now: new Date(),
});
if (!tls.ok) {
  throw new Error(`revocation mTLS listener: ${tls.error}`);
}

const app = await buildServer({
  ...(tls.value ? { serverFactory: tls.value.listener.serverFactory } : {}),
  db,
  controlPlaneAuth,
  ...outgoing.value,
  auditUrl: env.AUDIT_URL,
  didDomain: env.REVOCATION_DID_DOMAIN,
  subscriberUrls: env.REVOCATION_SUBSCRIBER_URLS,
  statusTtlMs: env.REVOCATION_STATUS_TTL_MS,
});

try {
  await app.listen({ port: env.PORT, host: "0.0.0.0" });
  if (tls.value) await tls.value.listener.listen(tls.value.port, "0.0.0.0");
} catch (err: unknown) {
  app.log.error(err);
  process.exit(1);
}

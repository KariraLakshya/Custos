import {
  checkServiceKey,
  createApiKeyStore,
  createControlPlaneGuard,
} from "@custos/control-plane-auth";
import { createDb } from "./db/client.js";
import { loadIdentityEnv } from "./env.js";
import { createIssuerKey } from "./keys/issuer-key.js";
import { buildServer } from "./server.js";

const env = loadIdentityEnv();
const db = createDb(env.DATABASE_URL);
const controlPlaneAuth = createControlPlaneGuard({
  keys: createApiKeyStore(db),
  clock: { now: () => new Date() },
});

// Refuse to boot on a service key that can't do its job (ADR 0008 §6).
const serviceKeyCheck = await checkServiceKey({
  ...controlPlaneAuth,
  token: env.IDENTITY_SERVICE_KEY,
  scopes: ["status:allocate", "audit:write"],
});
if (!serviceKeyCheck.ok) {
  throw new Error(`IDENTITY_SERVICE_KEY: ${serviceKeyCheck.error}`);
}

const app = await buildServer({
  db,
  controlPlaneAuth,
  serviceKey: env.IDENTITY_SERVICE_KEY,
  auditUrl: env.AUDIT_URL,
  didDomain: env.IDENTITY_DID_DOMAIN,
  revocationUrl: env.REVOCATION_URL,
  issuerKey: createIssuerKey(env),
  registrationProofMaxSkewSeconds: env.IDENTITY_REGISTRATION_PROOF_MAX_SKEW_SECONDS,
});

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

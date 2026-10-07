import {
  createApiKeyStore,
  createControlPlaneGuard,
  resolveOutgoingServiceAuth,
} from "@custos/control-plane-auth";
import { createDb } from "./db/client.js";
import { loadIdentityEnv } from "./env.js";
import { createIssuerKey } from "./keys/issuer-key.js";
import { buildServer } from "./server.js";
import { createOperatorSsoFromEnv } from "./sso/boot.js";

const env = loadIdentityEnv();
const db = createDb(env.DATABASE_URL);
const controlPlaneAuth = createControlPlaneGuard({
  keys: createApiKeyStore(db),
  clock: { now: () => new Date() },
});

// Exactly one of an API key or a client certificate, checked before
// serving (ADR 0008 §6, ADR 0009).
const outgoing = await resolveOutgoingServiceAuth({
  service: "identity",
  scopes: ["status:allocate", "audit:write"],
  serviceKey: env.IDENTITY_SERVICE_KEY,
  mtls: { certFile: env.IDENTITY_MTLS_CERT, keyFile: env.IDENTITY_MTLS_KEY, caFile: env.MTLS_CA },
  guard: controlPlaneAuth,
  now: new Date(),
});
if (!outgoing.ok) {
  throw new Error(`identity: ${outgoing.error}`);
}

// Operator SSO (ADR 0010), if configured: checked before serving.
const operatorSso = await createOperatorSsoFromEnv(env, createApiKeyStore(db));
if (!operatorSso.ok) {
  throw new Error(`identity SSO: ${operatorSso.error}`);
}

const app = await buildServer({
  ...(operatorSso.value ? { operatorSso: operatorSso.value } : {}),
  db,
  controlPlaneAuth,
  ...outgoing.value,
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

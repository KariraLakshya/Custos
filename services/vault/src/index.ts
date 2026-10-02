import { createLocalSecretCipher } from "@custos/core";
import {
  createMockDatabaseConnector,
  createMockSlackConnector,
  createStripeConnector,
} from "@custos/connectors";
import {
  checkServiceKey,
  createApiKeyStore,
  createControlPlaneGuard,
} from "@custos/control-plane-auth";
import { createDb } from "./db/client.js";
import { loadVaultEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadVaultEnv();
const db = createDb(env.DATABASE_URL);
const cipher = createLocalSecretCipher(Buffer.from(env.VAULT_MASTER_KEY, "hex"));
const connectors = [
  createStripeConnector(),
  createMockSlackConnector(),
  createMockDatabaseConnector(),
];

const controlPlaneAuth = createControlPlaneGuard({
  keys: createApiKeyStore(db),
  clock: { now: () => new Date() },
});

// Refuse to boot on a service key that can't do its job (ADR 0008 §6).
const serviceKeyCheck = await checkServiceKey({
  ...controlPlaneAuth,
  token: env.VAULT_SERVICE_KEY,
  scope: "audit:write",
});
if (!serviceKeyCheck.ok) {
  throw new Error(`VAULT_SERVICE_KEY: ${serviceKeyCheck.error}`);
}

const app = await buildServer({
  db,
  controlPlaneAuth,
  serviceKey: env.VAULT_SERVICE_KEY,
  cipher,
  connectors,
  revocationUrl: env.REVOCATION_URL,
  revocationIssuerDid: env.REVOCATION_ISSUER_DID,
  trustedIssuerDid: env.VAULT_TRUSTED_ISSUER_DID,
  publicUrl: env.VAULT_PUBLIC_URL,
  tokenProofMaxSkewSeconds: env.VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS,
  revocationMaxStalenessMs: env.REVOCATION_MAX_STALENESS_MS,
  revocationResyncIntervalMs: env.REVOCATION_RESYNC_INTERVAL_MS,
  auditUrl: env.AUDIT_URL,
});

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

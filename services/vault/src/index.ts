import { createLocalSecretCipher } from "@custos/core";
import {
  createMockDatabaseConnector,
  createMockSlackConnector,
  createStripeConnector,
} from "@custos/connectors";
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

const app = await buildServer({
  db,
  cipher,
  connectors,
  revocationUrl: env.REVOCATION_URL,
  revocationIssuerDid: env.REVOCATION_ISSUER_DID,
  trustedIssuerDid: env.VAULT_TRUSTED_ISSUER_DID,
  revocationMaxStalenessMs: env.REVOCATION_MAX_STALENESS_MS,
  revocationResyncIntervalMs: env.REVOCATION_RESYNC_INTERVAL_MS,
  auditUrl: env.AUDIT_URL,
});

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

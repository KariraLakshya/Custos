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

const app = await buildServer({ db, cipher, connectors });

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

import { createDb } from "./db/client.js";
import { loadIdentityEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadIdentityEnv();
const db = createDb(env.DATABASE_URL);
const app = buildServer({ db, didDomain: env.IDENTITY_DID_DOMAIN });

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

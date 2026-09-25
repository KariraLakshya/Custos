import { createDb } from "./db/client.js";
import { loadIdentityEnv } from "./env.js";
import { createIssuerKey } from "./keys/issuer-key.js";
import { buildServer } from "./server.js";

const env = loadIdentityEnv();
const db = createDb(env.DATABASE_URL);
const app = await buildServer({
  db,
  didDomain: env.IDENTITY_DID_DOMAIN,
  revocationUrl: env.REVOCATION_URL,
  issuerKey: createIssuerKey(env),
  registrationProofMaxSkewSeconds: env.IDENTITY_REGISTRATION_PROOF_MAX_SKEW_SECONDS,
});

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

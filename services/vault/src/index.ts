import { loadVaultEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadVaultEnv();
const app = buildServer();

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

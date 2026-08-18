import { loadIdentityEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadIdentityEnv();
const app = buildServer();

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err: unknown) => {
  app.log.error(err);
  process.exit(1);
});

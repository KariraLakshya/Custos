import { loadDashboardEnv } from "./env.js";
import { buildServer } from "./server.js";

const env = loadDashboardEnv();
const server = buildServer();

server.listen(env.PORT, "0.0.0.0", () => {
  console.log(`custos dashboard listening on http://localhost:${env.PORT}`);
});

import { createLogger } from "@custos/observability";
import Fastify from "fastify";

export function buildServer(): ReturnType<typeof Fastify> {
  const app = Fastify({ loggerInstance: createLogger({ level: "silent" }) });

  app.get("/health", async () => ({ status: "ok", service: "audit" }));

  return app;
}

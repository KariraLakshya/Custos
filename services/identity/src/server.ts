import { randomUUID } from "node:crypto";
import { createLocalKeyProvider, type KeyProvider } from "@custos/core";
import { createLogger } from "@custos/observability";
import Fastify from "fastify";
import { z } from "zod";
import { registerAgent } from "./agents/register.js";
import { findAgentDidDocumentById } from "./agents/find.js";
import { createHttpStatusAllocator, type StatusAllocator } from "./agents/status-allocator.js";
import type { IdentityDb } from "./db/client.js";

// Re-exported so other packages' e2e tests can boot a real instance of this
// service in-process (CLAUDE.md's "packages declare explicit exports" rule:
// this is the one sanctioned surface, not a deep import into ./db/client.js).
export { createDb } from "./db/client.js";

const agentIdParamsSchema = z.object({ id: z.string().uuid() });

export function buildServer(options: {
  readonly db: IdentityDb;
  readonly didDomain?: string;
  readonly keyProvider?: KeyProvider;
  readonly revocationUrl?: string;
  readonly statusAllocator?: StatusAllocator;
}): ReturnType<typeof Fastify> {
  const app = Fastify({ loggerInstance: createLogger({ level: "silent" }) });
  const { db } = options;
  const keyProvider = options.keyProvider ?? createLocalKeyProvider();
  const domain = options.didDomain ?? "localhost";
  const statusAllocator =
    options.statusAllocator ??
    createHttpStatusAllocator({ revocationUrl: options.revocationUrl ?? "http://localhost:4003" });

  app.get("/health", async () => ({ status: "ok", service: "identity" }));

  app.post("/agents", async (_request, reply) => {
    const result = await registerAgent({
      db,
      keyProvider,
      statusAllocator,
      domain,
      agentId: randomUUID(),
      now: new Date(),
    });
    if (!result.ok) {
      reply.code(502);
      return { error: result.error };
    }
    reply.code(201);
    return result.value;
  });

  app.get("/agents/:id/did.json", async (request, reply) => {
    const params = agentIdParamsSchema.safeParse(request.params);
    if (!params.success) {
      reply.code(400);
      return { error: "INVALID_AGENT_ID" };
    }
    const didDocument = await findAgentDidDocumentById(db, params.data.id);
    if (!didDocument) {
      reply.code(404);
      return { error: "AGENT_NOT_FOUND" };
    }
    return didDocument;
  });

  return app;
}

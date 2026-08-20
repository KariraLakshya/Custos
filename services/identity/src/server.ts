import { buildDidWebDocument, generateKeyPair, type Ed25519KeyPair } from "@custos/core";
import { createLogger } from "@custos/observability";
import Fastify from "fastify";

export function buildServer(options?: {
  readonly didDomain?: string;
  readonly keyPair?: Ed25519KeyPair;
}): ReturnType<typeof Fastify> {
  const app = Fastify({ loggerInstance: createLogger({ level: "silent" }) });

  // Phase 0 only: one in-memory keypair for the life of the process, never
  // persisted. Phase 1 replaces this with a per-agent identity backed by a
  // KMS-shaped key provider; `options.keyPair` exists only so tests can
  // prove the served document against a known key.
  const { publicKey } = options?.keyPair ?? generateKeyPair();
  const didDocument = buildDidWebDocument({ domain: options?.didDomain ?? "localhost", publicKey });

  app.get("/health", async () => ({ status: "ok", service: "identity" }));
  app.get("/.well-known/did.json", async () => didDocument);

  return app;
}

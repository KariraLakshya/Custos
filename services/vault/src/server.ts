import {
  createLocalKeyProvider,
  type KeyProvider,
  type SecretCipher,
  type SignedCredential,
} from "@custos/core";
import type { Connector } from "@custos/connectors";
import { createLogger } from "@custos/observability";
import Fastify from "fastify";
import { z } from "zod";
import { storeToolCredential } from "./credentials/store.js";
import { issueToolToken } from "./tokens/issue.js";
import { invokeTool } from "./calls/invoke.js";
import type { VaultDb } from "./db/client.js";

// Re-exported so other packages' e2e tests can boot a real instance of this
// service in-process (see services/identity/src/server.ts's identical note).
export { createDb } from "./db/client.js";

const storeCredentialSchema = z.object({
  tool: z.string().min(1),
  secret: z.string().min(1),
});

const issueTokenSchema = z.object({
  tool: z.string().min(1),
  action: z.string().min(1),
  credential: z.object({ issuer: z.string().min(1) }).passthrough(),
});

const callSchema = z.object({
  token: z.string().min(1),
  action: z.string().min(1),
  input: z.unknown().optional(),
});

function statusFor(code: string): number {
  if (code === "UNKNOWN_TOOL") return 404;
  if (
    code === "INVALID_AGENT_CREDENTIAL" ||
    code === "INVALID_TOKEN" ||
    code === "ACTION_MISMATCH"
  ) {
    return 401;
  }
  if (code === "UNKNOWN_ACTION" || code === "INVALID_INPUT") return 400;
  return 502;
}

/**
 * Requires a caller-provided `cipher` (no default: there is no safe default
 * symmetric key — see docs/adr/0004-vault-credential-encryption.md). The
 * vault's own token-signing keypair is generated once per server build, via
 * `keyProvider` (defaults to the same in-memory dev KMS stand-in identity
 * uses) — this is a Phase 2 vault-internal signing identity, not yet a
 * published did:web document (nothing outside this process verifies these
 * tokens today).
 */
export async function buildServer(options: {
  readonly db: VaultDb;
  readonly cipher: SecretCipher;
  readonly connectors?: readonly Connector[];
  readonly keyProvider?: KeyProvider;
  readonly clock?: { now(): Date };
}): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({ loggerInstance: createLogger({ level: "silent" }) });
  const { db, cipher } = options;
  const connectorsByTool = new Map(
    (options.connectors ?? []).map((connector) => [connector.tool, connector]),
  );
  const keyProvider = options.keyProvider ?? createLocalKeyProvider();
  const clock = options.clock ?? { now: () => new Date() };
  const { keyId: signingKeyId, publicKey: vaultPublicKey } = await keyProvider.createKeyPair();

  app.get("/health", async () => ({ status: "ok", service: "vault" }));

  app.post("/credentials", async (request, reply) => {
    const body = storeCredentialSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: "INVALID_INPUT" };
    }
    await storeToolCredential({ db, cipher, tool: body.data.tool, secret: body.data.secret });
    reply.code(201);
    return { tool: body.data.tool };
  });

  app.post("/tokens", async (request, reply) => {
    const body = issueTokenSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: "INVALID_INPUT" };
    }
    const result = await issueToolToken({
      db,
      keyProvider,
      signingKeyId,
      agentCredential: body.data.credential as unknown as SignedCredential,
      tool: body.data.tool,
      action: body.data.action,
      now: clock.now(),
    });
    if (!result.ok) {
      reply.code(statusFor(result.error.code));
      return { error: result.error };
    }
    return result.value;
  });

  app.post("/call", async (request, reply) => {
    const body = callSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: "INVALID_INPUT" };
    }
    const result = await invokeTool({
      db,
      cipher,
      connectors: connectorsByTool,
      token: body.data.token,
      vaultPublicKey,
      action: body.data.action,
      input: body.data.input,
      now: clock.now(),
    });
    if (!result.ok) {
      reply.code(statusFor(result.error.code));
      return { error: result.error };
    }
    return { result: result.value };
  });

  return app;
}

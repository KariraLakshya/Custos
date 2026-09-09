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
import { createRevocationCache, type RevocationCache } from "./revocation/cache.js";
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

const tombstoneSchema = z.object({
  tombstone: z.string().min(1),
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
  // A revoked agent is authenticated but no longer permitted, and a stale
  // local view means we cannot safely say either way — both deny.
  if (code === "AGENT_REVOKED") return 403;
  if (code === "REVOCATION_STATE_STALE") return 503;
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
  readonly revocation?: RevocationCache;
  readonly revocationIssuerDid?: string;
  readonly revocationUrl?: string;
  readonly revocationMaxStalenessMs?: number;
  /** Omitted in tests, which drive the cache directly and deterministically. */
  readonly revocationResyncIntervalMs?: number;
}): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({ loggerInstance: createLogger({ level: "silent" }) });
  const { db, cipher } = options;
  const connectorsByTool = new Map(
    (options.connectors ?? []).map((connector) => [connector.tool, connector]),
  );
  const keyProvider = options.keyProvider ?? createLocalKeyProvider();
  const clock = options.clock ?? { now: () => new Date() };
  const { keyId: signingKeyId, publicKey: vaultPublicKey } = await keyProvider.createKeyPair();

  const revocation =
    options.revocation ??
    createRevocationCache({
      issuerDid: options.revocationIssuerDid ?? "did:web:localhost%3A4003",
      revocationUrl: options.revocationUrl ?? "http://localhost:4003",
      maxStalenessMs: options.revocationMaxStalenessMs ?? 30_000,
      // A revoked agent is cut off at the tool itself, not merely refused a
      // fresh token — "adapters honour revocation" (build plan, Phase 3).
      onRevoked: async (agentDid) => {
        await Promise.all(
          [...connectorsByTool.values()].map(async (connector) => {
            try {
              await connector.revoke(agentDid);
            } catch (error) {
              app.log.error({ tool: connector.tool, err: error }, "connector revoke failed");
            }
          }),
        );
      },
    });

  /**
   * Pushed tombstones are the fast path; this periodic resync is the safety
   * net that closes the window if a push is missed, and it is what keeps the
   * cache inside its staleness bound. An initial sync runs at boot, because
   * a vault that has never heard from the revocation service starts stale
   * and must deny until it has.
   */
  if (options.revocationResyncIntervalMs !== undefined) {
    const runResync = async (): Promise<void> => {
      const result = await revocation.resync(clock.now());
      if (!result.ok) {
        app.log.warn({ reason: result.error.reason }, "revocation resync failed; state is ageing");
      }
    };
    await runResync();
    const timer = setInterval(() => void runResync(), options.revocationResyncIntervalMs);
    timer.unref();
    app.addHook("onClose", async () => clearInterval(timer));
  }

  app.get("/health", async () => ({ status: "ok", service: "vault" }));

  app.get("/revocations", async () => revocation.status(clock.now()));

  // Push endpoint the revocation service broadcasts to. Deliberately
  // unauthenticated at the transport level: the tombstone's own signature is
  // what is trusted, verified against the revocation service's published DID
  // document, so an unsigned or forged push is rejected here.
  app.post("/revocations", async (request, reply) => {
    const body = tombstoneSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: "INVALID_INPUT" };
    }
    const accepted = await revocation.acceptTombstone(body.data.tombstone, clock.now());
    if (!accepted.ok) {
      reply.code(accepted.error.code === "INVALID_TOMBSTONE" ? 401 : 502);
      return { error: accepted.error };
    }
    reply.code(202);
    return { revoked: accepted.value };
  });

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
      revocation,
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
      revocation,
    });
    if (!result.ok) {
      reply.code(statusFor(result.error.code));
      return { error: result.error };
    }
    return { result: result.value };
  });

  return app;
}

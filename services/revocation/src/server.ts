import { buildDidWebDocument, createLocalKeyProvider, type KeyProvider } from "@custos/core";
import { createLogger } from "@custos/observability";
import Fastify from "fastify";
import { z } from "zod";
import { allocateStatusListIndex } from "./agents/allocate.js";
import { listTombstones, revokeAgent } from "./revoke.js";
import { buildStatusListCredential } from "./status/credential.js";
import { createHttpBroadcaster, type TombstoneBroadcaster } from "./broadcast.js";
import type { RevocationDb } from "./db/client.js";

// Re-exported so other packages' e2e tests can boot a real instance of this
// service in-process, matching services/{identity,vault}/src/server.ts.
export { createDb } from "./db/client.js";

const allocateSchema = z.object({
  agentId: z.string().uuid(),
  agentDid: z.string().min(1),
});

const revokeSchema = z.object({
  agentId: z.string().uuid(),
  reason: z.string().min(1).optional(),
});

function statusFor(code: string): number {
  if (code === "UNKNOWN_AGENT") return 404;
  return 502;
}

/**
 * The control plane for revocation. It owns status list index allocation as
 * well as revocation state, so it can answer both without the identity
 * service being reachable — revocation is the emergency path and must not
 * inherit another service's availability.
 *
 * Its signing keypair is generated once per server build via `keyProvider`
 * (the same in-memory dev KMS stand-in identity and vault use) and published
 * at `/.well-known/did.json`, so subscribers can independently verify every
 * tombstone and the status list credential.
 */
export async function buildServer(options: {
  readonly db: RevocationDb;
  readonly didDomain?: string;
  readonly keyProvider?: KeyProvider;
  readonly broadcaster?: TombstoneBroadcaster;
  readonly subscriberUrls?: readonly string[];
  readonly statusTtlMs?: number;
  readonly clock?: { now(): Date };
}): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({ loggerInstance: createLogger({ level: "silent" }) });
  const { db } = options;
  const keyProvider = options.keyProvider ?? createLocalKeyProvider();
  const domain = options.didDomain ?? "localhost:4003";
  const clock = options.clock ?? { now: () => new Date() };
  const broadcaster =
    options.broadcaster ?? createHttpBroadcaster({ subscriberUrls: options.subscriberUrls ?? [] });

  const { keyId, publicKey } = await keyProvider.createKeyPair();
  const didDocument = buildDidWebDocument({ domain, publicKey });
  const serviceDid = didDocument.id;
  const verificationMethodId = didDocument.verificationMethod[0].id;
  const statusListCredentialUrl = `${
    domain.startsWith("localhost") || domain.startsWith("127.0.0.1") ? "http" : "https"
  }://${domain}/status/revocation`;

  const tombstoneSigner = { sign: (data: Uint8Array) => keyProvider.sign(keyId, data) };
  const credentialSigner = {
    id: verificationMethodId,
    sign: (input: { readonly data: Uint8Array }) => keyProvider.sign(keyId, input.data),
  };

  app.get("/health", async () => ({ status: "ok", service: "revocation" }));

  // The key every subscriber verifies tombstones against.
  app.get("/.well-known/did.json", async () => didDocument);

  // Called by the identity service during registration, before it issues the
  // agent's credential — the returned index is embedded in that credential's
  // `credentialStatus`.
  app.post("/agents", async (request, reply) => {
    const body = allocateSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: "INVALID_INPUT" };
    }
    const result = await allocateStatusListIndex({
      db,
      agentId: body.data.agentId,
      agentDid: body.data.agentDid,
    });
    if (!result.ok) {
      reply.code(502);
      return { error: result.error };
    }
    reply.code(201);
    return { ...result.value, statusListCredential: statusListCredentialUrl };
  });

  app.post("/revocations", async (request, reply) => {
    const body = revokeSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: "INVALID_INPUT" };
    }
    const result = await revokeAgent({
      db,
      broadcaster,
      signer: tombstoneSigner,
      agentId: body.data.agentId,
      ...(body.data.reason === undefined ? {} : { reason: body.data.reason }),
      now: clock.now(),
    });
    if (!result.ok) {
      reply.code(statusFor(result.error.code));
      return { error: result.error };
    }
    return result.value;
  });

  // Resync: a subscriber bootstrapping at boot, or catching up after a
  // missed push, replays these through the same verification path.
  app.get("/revocations", async (_request, reply) => {
    const result = await listTombstones({ db, signer: tombstoneSigner });
    if (!result.ok) {
      reply.code(502);
      return { error: result.error };
    }
    return { tombstones: result.value, asOf: clock.now().toISOString() };
  });

  app.get("/status/revocation", async (_request, reply) => {
    const result = await buildStatusListCredential({
      db,
      issuerDid: serviceDid,
      signer: credentialSigner,
      statusListCredentialUrl,
      now: clock.now(),
      ...(options.statusTtlMs === undefined ? {} : { ttlMs: options.statusTtlMs }),
    });
    if (!result.ok) {
      reply.code(502);
      return { error: result.error };
    }
    return result.value;
  });

  return app;
}

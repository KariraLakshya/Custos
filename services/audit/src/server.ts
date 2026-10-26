import { auditEventSchema } from "@custos/contracts";
import {
  principalOf,
  requireScope,
  type ControlPlaneGuard,
  type EnvoyOnlyTlsListener,
} from "@custos/control-plane-auth";
import { buildDidWebDocument, type KeyProvider } from "@custos/core";
import { createLogger } from "@custos/observability";
import Fastify from "fastify";
import { appendAuditRecord, chainUnchainedRecords } from "./records/append.js";
import { listAuditEntries } from "./records/list.js";
import { latestSeal, sealOnce, type SealError } from "./records/seal.js";
import type { AuditDb } from "./db/client.js";
import type { Result } from "@custos/contracts";

declare module "fastify" {
  interface FastifyInstance {
    /** Seals the head now, if it moved (ADR 0017 §2); the timer calls the same. */
    auditLedger: { sealOnce(): Promise<Result<number | null, SealError>> };
  }
}

// Re-exported so other packages' e2e tests can boot a real instance of this
// service in-process, matching services/{identity,vault,revocation}/src/server.ts.
export { createDb } from "./db/client.js";

/**
 * The audit trail as a sealed ledger (ADR 0017). Its own `did:web` signing
 * identity, published at `/.well-known/did.json`, signs the seals: periodic
 * signatures over the head of the hash chain. Appends are chained under a
 * lock and never signed; reads are served exactly as stored and never signed.
 *
 * `signingKey` is required, with no default: seals are verified long after
 * they are made, so the key must outlive the process (local seed or KMS).
 */
export async function buildServer(options: {
  readonly db: AuditDb;
  /** Required, no default: `POST /records` is never open (ADR 0008). */
  readonly controlPlaneAuth: ControlPlaneGuard;
  /**
   * Serves the same app on a second, Envoy-only TLS listener too (ADR 0009):
   * `createEnvoyOnlyTlsListener(...).serverFactory`.
   */
  readonly serverFactory?: EnvoyOnlyTlsListener["serverFactory"];
  readonly didDomain?: string;
  readonly signingKey: { readonly keyProvider: KeyProvider; readonly keyId: string };
  /** Seal on this interval. Unset (tests): only `app.auditLedger.sealOnce()` seals. */
  readonly sealIntervalMs?: number;
  readonly clock?: { now(): Date };
}): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({
    loggerInstance: createLogger({ level: "silent" }),
    ...(options.serverFactory === undefined ? {} : { serverFactory: options.serverFactory }),
  });
  const { db } = options;
  const { keyProvider, keyId } = options.signingKey;
  const domain = options.didDomain ?? "localhost:4004";
  const clock = options.clock ?? { now: () => new Date() };

  const didDocument = buildDidWebDocument({
    domain,
    publicKey: await keyProvider.getPublicKey(keyId),
  });
  const signer = { sign: (data: Uint8Array) => keyProvider.sign(keyId, data) };
  // Rows from before the ledger, chained once, before anything is appended.
  await chainUnchainedRecords(db);

  const seal = () => sealOnce({ db, signer, log: didDocument.id, now: clock.now() });
  app.decorate("auditLedger", { sealOnce: seal });
  if (options.sealIntervalMs !== undefined) {
    const timer = setInterval(() => {
      // A failure (KMS unreachable) skips this tick; appends never wait on it.
      void seal().then(
        (result) => {
          if (!result.ok) app.log.warn({ code: result.error.code }, "audit seal failed");
        },
        (error: unknown) => app.log.error({ err: error }, "audit seal failed"),
      );
    }, options.sealIntervalMs);
    timer.unref();
    app.addHook("onClose", async () => clearInterval(timer));
  }

  app.get("/health", async () => ({ status: "ok", service: "audit" }));

  // The key every seal is verified against.
  app.get("/.well-known/did.json", async () => didDocument);

  // Called by the vault and the other services to report one action outcome.
  // Fire-and-forget from the caller's side (CLAUDE.md section 3). Service keys
  // only: an open endpoint would let anyone add evidence (ADR 0008). The
  // caller is recorded as `reportedBy` inside the hashed entry (ADR 0017 §4).
  const recordsGuard = requireScope({ ...options.controlPlaneAuth, scope: "audit:write" });
  app.post("/records", { preHandler: recordsGuard }, async (request, reply) => {
    const body = auditEventSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: "INVALID_INPUT" };
    }
    const caller = principalOf(request);
    await appendAuditRecord({
      db,
      event: body.data,
      reportedBy: { kind: caller.kind, id: caller.id, name: caller.name },
      now: clock.now(),
    });
    reply.code(201);
    return { stored: true };
  });

  // The ledger and its newest seal, exactly as stored; nothing is signed here.
  // The caller checks the chain against the seal (and any seal it already
  // holds) with `verifyAuditLedger`.
  app.get("/records", async (request, reply) => {
    // Every entry is checked against the seal and the DID document above, so
    // a same-origin restriction would add nothing. This lets the dashboard
    // (apps/dashboard) read it directly from the browser.
    reply.header("access-control-allow-origin", "*");
    const query = request.query as { readonly agentId?: string };
    const entries = await listAuditEntries({ db, agentDid: query.agentId });
    return { entries, seal: await latestSeal(db) };
  });

  return app;
}

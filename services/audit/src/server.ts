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
import {
  copySeals,
  createCopyVerdicts,
  latestSeal,
  sealOnce,
  sealStatus,
  type CopyError,
  type SealError,
} from "./records/seal.js";
import type { AuditDb } from "./db/client.js";
import type { SealStore } from "@custos/audit-client";
import type { Result } from "@custos/contracts";

declare module "fastify" {
  interface FastifyInstance {
    auditLedger: {
      /** Seals the head now, if it moved (ADR 0017 §2); the timer calls the same. */
      sealOnce(): Promise<Result<number | null, SealError>>;
      /** Copies uncopied seals to the seal store (part 2a); an error without one. */
      copyOnce(): Promise<Result<number, CopyError>>;
    };
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
  /** Seal (and copy) on this interval. Unset (tests): only `app.auditLedger` calls do. */
  readonly sealIntervalMs?: number;
  /**
   * Where seals are copied outside this database (ADR 0017 part 2a). Unset:
   * nothing is copied, and `GET /seals/status` says so.
   */
  readonly sealStore?: SealStore;
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
  const currentKey = didDocument.verificationMethod[0].publicKeyMultibase;
  // Rows from before the ledger, chained once, before anything is appended.
  await chainUnchainedRecords(db);

  const seal = () =>
    sealOnce({ db, signer, log: didDocument.id, key: currentKey, now: clock.now() });
  const verdicts = createCopyVerdicts({ log: didDocument.id, key: currentKey });
  // A code only: the reason can name the seal server's host, and this route is open.
  let lastCopyError: { readonly code: CopyError["code"] } | null = null;
  const copy = async (): Promise<Result<number, CopyError>> => {
    if (options.sealStore === undefined) {
      return { ok: false, error: { code: "COPY_FAILED", reason: "no seal store configured" } };
    }
    const result = await copySeals({
      db,
      store: options.sealStore,
      log: didDocument.id,
      verdicts,
      now: clock.now(),
    });
    lastCopyError = result.ok ? null : { code: result.error.code };
    return result;
  };
  app.decorate("auditLedger", { sealOnce: seal, copyOnce: copy });
  if (options.sealIntervalMs !== undefined) {
    let running = false;
    const timer = setInterval(() => {
      // One tick at a time. A failure (KMS or the seal store unreachable)
      // skips this tick; appends never wait on either.
      if (running) return;
      running = true;
      void (async () => {
        const sealed = await seal();
        if (!sealed.ok) app.log.warn({ code: sealed.error.code }, "audit seal failed");
        if (options.sealStore !== undefined) {
          const copied = await copy();
          if (!copied.ok) app.log.warn({ code: copied.error.code }, "audit seal copy failed");
        }
      })()
        .catch((error: unknown) => app.log.error({ err: error }, "audit seal tick failed"))
        .finally(() => {
          running = false;
        });
    }, options.sealIntervalMs);
    timer.unref();
    app.addHook("onClose", async () => clearInterval(timer));
  }

  app.get("/health", async () => ({ status: "ok", service: "audit" }));

  // How far sealing and copying have got (ADR 0017 part 2a). The newest
  // entries are only as safe as the newest copy, so the lag is shown here.
  app.get("/seals/status", async () => ({
    ...(await sealStatus(db, verdicts)),
    sealStore: options.sealStore === undefined ? "not configured" : "configured",
    lastCopyError,
  }));

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
    // The seal first, then the entries: a seal only covers entries already
    // committed and the log only grows, so entries read afterwards always
    // include the sealed one. The other order lets a seal made between the two
    // reads cover an entry the response lacks, which reads as TRUNCATED.
    const seal = await latestSeal(db, currentKey);
    const entries = await listAuditEntries({ db, agentDid: query.agentId });
    return { entries, seal };
  });

  return app;
}

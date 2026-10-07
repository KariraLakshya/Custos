import {
  controlPlaneEvent,
  createHttpAuditReporter,
  type AuditReporter,
} from "@custos/audit-client";
import {
  principalOf,
  requireScope,
  type ControlPlaneGuard,
  type EnvoyOnlyTlsListener,
} from "@custos/control-plane-auth";
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

function defaultAuditReporter(
  options: {
    readonly auditUrl?: string;
    readonly serviceKey?: string;
    readonly mtlsFetch?: typeof fetch;
  },
  app: { readonly log: { warn(obj: object, msg: string): void } },
): AuditReporter {
  // Without a key or a certificate every report would be refused, and audit
  // loss is a bug (CLAUDE.md section 3), so refuse to build instead.
  if (options.serviceKey === undefined && options.mtlsFetch === undefined) {
    throw new Error(
      "revocation: serviceKey or mtlsFetch is required when auditReporter is not injected",
    );
  }
  return createHttpAuditReporter({
    auditUrl: options.auditUrl ?? "http://localhost:4004",
    ...(options.serviceKey === undefined ? {} : { serviceKey: options.serviceKey }),
    ...(options.mtlsFetch === undefined ? {} : { fetchImpl: options.mtlsFetch }),
    onError: (error) => app.log.warn({ err: error }, "audit report failed"),
  });
}

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
  /** Required, no default: allocation and revocation are never open (ADR 0008). */
  readonly controlPlaneAuth: ControlPlaneGuard;
  readonly didDomain?: string;
  readonly keyProvider?: KeyProvider;
  readonly broadcaster?: TombstoneBroadcaster;
  readonly subscriberUrls?: readonly string[];
  readonly statusTtlMs?: number;
  readonly clock?: { now(): Date };
  readonly auditUrl?: string;
  /** This service's key for the audit service; required unless `auditReporter` is injected. */
  readonly serviceKey?: string;
  /**
   * Calls other Custos services through Envoy with this service's client
   * certificate (ADR 0009), instead of `serviceKey`.
   */
  readonly mtlsFetch?: typeof fetch;
  /**
   * Serves the same app on a second, Envoy-only TLS listener too (ADR 0009):
   * `createEnvoyOnlyTlsListener(...).serverFactory`.
   */
  readonly serverFactory?: EnvoyOnlyTlsListener["serverFactory"];
  /** Injectable for tests; defaults to a fire-and-forget HTTP push. */
  readonly auditReporter?: AuditReporter;
}): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({
    loggerInstance: createLogger({ level: "silent" }),
    ...(options.serverFactory === undefined ? {} : { serverFactory: options.serverFactory }),
  });
  const { db } = options;
  const keyProvider = options.keyProvider ?? createLocalKeyProvider();
  const domain = options.didDomain ?? "localhost:4003";
  const clock = options.clock ?? { now: () => new Date() };
  const broadcaster =
    options.broadcaster ?? createHttpBroadcaster({ subscriberUrls: options.subscriberUrls ?? [] });
  const auditReporter = options.auditReporter ?? defaultAuditReporter(options, app);

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
  // Service key only (`status:allocate`): an open endpoint let anyone
  // exhaust the status list's slots (ADR 0008).
  // Both writes are audited with the caller who made them (ADR 0008 §7).
  const allocateGuard = requireScope({
    ...options.controlPlaneAuth,
    scope: "status:allocate",
    onScopeDenied: (principal) =>
      auditReporter.report(
        controlPlaneEvent({
          principal,
          scope: "status:allocate",
          action: "status.allocate",
          decision: "deny",
        }),
      ),
  });
  app.post("/agents", { preHandler: allocateGuard }, async (request, reply) => {
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
    auditReporter.report(
      controlPlaneEvent({
        principal: principalOf(request),
        scope: "status:allocate",
        action: "status.allocate",
        decision: "allow",
        agentDid: body.data.agentDid,
      }),
    );
    reply.code(201);
    return { ...result.value, statusListCredential: statusListCredentialUrl };
  });

  const revokeGuard = requireScope({
    ...options.controlPlaneAuth,
    scope: "agents:revoke",
    onScopeDenied: (principal) =>
      auditReporter.report(
        controlPlaneEvent({
          principal,
          scope: "agents:revoke",
          action: "agents.revoke",
          decision: "deny",
        }),
      ),
  });
  app.post("/revocations", { preHandler: revokeGuard }, async (request, reply) => {
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
    auditReporter.report(
      controlPlaneEvent({
        principal: principalOf(request),
        scope: "agents:revoke",
        action: "agents.revoke",
        decision: "allow",
        agentDid: result.value.agentDid,
        ...(body.data.reason === undefined ? {} : { reason: body.data.reason }),
      }),
    );
    return result.value;
  });

  // Resync: a subscriber bootstrapping at boot, or catching up after a
  // missed push, replays these through the same verification path.
  app.get("/revocations", async (_request, reply) => {
    // Every tombstone is independently verifiable against the DID document
    // above, so a same-origin restriction would only be theatre — this lets
    // Phase 5's dashboard (apps/dashboard) read it directly from the browser.
    reply.header("access-control-allow-origin", "*");
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

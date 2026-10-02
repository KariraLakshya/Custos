import { randomUUID } from "node:crypto";
import {
  controlPlaneEvent,
  createHttpAuditReporter,
  type AuditReporter,
} from "@custos/audit-client";
import { principalOf, requireScope, type ControlPlaneGuard } from "@custos/control-plane-auth";
import { buildDidWebDocument, type KeyProvider } from "@custos/core";
import { createLogger } from "@custos/observability";
import Fastify from "fastify";
import { z } from "zod";
import { registerAgent, type RegisterAgentError } from "./agents/register.js";
import { findAgentDidDocumentById } from "./agents/find.js";
import { createHttpStatusAllocator, type StatusAllocator } from "./agents/status-allocator.js";
import type { IdentityDb } from "./db/client.js";

// Re-exported so other packages' e2e tests can boot a real instance of this
// service in-process (CLAUDE.md's "packages declare explicit exports" rule:
// this is the one sanctioned surface, not a deep import into ./db/client.js).
export { createDb } from "./db/client.js";

const agentIdParamsSchema = z.object({ id: z.string().uuid() });

// Bounded: a multibase Ed25519 key is under 64 characters, a proof a few hundred.
const registerAgentSchema = z.object({
  publicKey: z.string().min(1).max(64),
  proof: z.string().min(1).max(4096),
});

function statusFor(code: RegisterAgentError["code"]): number {
  if (code === "INVALID_PUBLIC_KEY") return 400;
  if (code === "INVALID_REGISTRATION_PROOF") return 401;
  if (code === "KEY_ALREADY_REGISTERED") return 409;
  return 502;
}

function defaultStatusAllocator(options: {
  readonly revocationUrl?: string;
  readonly serviceKey?: string;
}): StatusAllocator {
  // Programmer or configuration error: without a key every registration
  // would fail at the revocation service, so refuse to build instead.
  if (options.serviceKey === undefined) {
    throw new Error("identity: serviceKey is required when statusAllocator is not injected");
  }
  return createHttpStatusAllocator({
    revocationUrl: options.revocationUrl ?? "http://localhost:4003",
    serviceKey: options.serviceKey,
  });
}

function defaultAuditReporter(
  options: { readonly auditUrl?: string; readonly serviceKey?: string },
  app: { readonly log: { warn(obj: object, msg: string): void } },
): AuditReporter {
  // Without a key every report would be refused, and audit loss is a bug
  // (CLAUDE.md section 3), so refuse to build instead.
  if (options.serviceKey === undefined) {
    throw new Error("identity: serviceKey is required when auditReporter is not injected");
  }
  return createHttpAuditReporter({
    auditUrl: options.auditUrl ?? "http://localhost:4004",
    serviceKey: options.serviceKey,
    onError: (error) => app.log.warn({ err: error }, "audit report failed"),
  });
}

/**
 * `issuerKey` is required, with no default: the identity service signs every
 * agent credential as issuer, and those credentials outlive the process, so
 * the key must be one that survives restarts — an imported dev seed or a KMS
 * key (ADR 0007 decision 4). An ephemeral default would silently invalidate
 * every credential on the next restart.
 */
export async function buildServer(options: {
  readonly db: IdentityDb;
  /** Required, no default: registering an agent needs an operator key (ADR 0008). */
  readonly controlPlaneAuth: ControlPlaneGuard;
  readonly didDomain?: string;
  readonly issuerKey: { readonly keyProvider: KeyProvider; readonly keyId: string };
  readonly revocationUrl?: string;
  /**
   * This service's key, with `status:allocate` and `audit:write`; required
   * unless both `statusAllocator` and `auditReporter` are injected.
   */
  readonly serviceKey?: string;
  readonly statusAllocator?: StatusAllocator;
  readonly auditUrl?: string;
  /** Injectable for tests; defaults to a fire-and-forget HTTP push. */
  readonly auditReporter?: AuditReporter;
  readonly clock?: { now(): Date };
  readonly registrationProofMaxSkewSeconds?: number;
}): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({ loggerInstance: createLogger({ level: "silent" }) });
  const { db, issuerKey } = options;
  const domain = options.didDomain ?? "localhost";
  const clock = options.clock ?? { now: () => new Date() };
  const proofMaxSkewSeconds = options.registrationProofMaxSkewSeconds ?? 60;

  // The issuer's own did:web identity, published so any verifier can check
  // an agent credential against it without trusting this service's database.
  const issuerDidDocument = buildDidWebDocument({
    domain,
    publicKey: await issuerKey.keyProvider.getPublicKey(issuerKey.keyId),
  });
  const issuer = {
    did: issuerDidDocument.id,
    verificationMethodId: issuerDidDocument.verificationMethod[0].id,
    keyProvider: issuerKey.keyProvider,
    keyId: issuerKey.keyId,
  };
  const statusAllocator = options.statusAllocator ?? defaultStatusAllocator(options);
  const auditReporter = options.auditReporter ?? defaultAuditReporter(options, app);

  app.get("/health", async () => ({ status: "ok", service: "identity" }));

  app.get("/.well-known/did.json", async () => issuerDidDocument);

  // Registration is audited with the operator who approved it (ADR 0008 §7).
  const registerGuard = requireScope({
    ...options.controlPlaneAuth,
    scope: "agents:register",
    onScopeDenied: (principal) =>
      auditReporter.report(
        controlPlaneEvent({
          principal,
          scope: "agents:register",
          action: "agents.register",
          decision: "deny",
        }),
      ),
  });
  app.post("/agents", { preHandler: registerGuard }, async (request, reply) => {
    const body = registerAgentSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: { code: "INVALID_INPUT" } };
    }
    const result = await registerAgent({
      db,
      issuer,
      statusAllocator,
      domain,
      agentId: randomUUID(),
      request: body.data,
      now: clock.now(),
      proofMaxSkewSeconds,
    });
    if (!result.ok) {
      reply.code(statusFor(result.error.code));
      return { error: result.error };
    }
    auditReporter.report(
      controlPlaneEvent({
        principal: principalOf(request),
        scope: "agents:register",
        action: "agents.register",
        decision: "allow",
        agentDid: result.value.did,
      }),
    );
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

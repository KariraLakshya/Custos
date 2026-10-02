import { requireScope, type ControlPlaneGuard } from "@custos/control-plane-auth";
import { buildDidWebDocument, createLocalKeyProvider, type KeyProvider } from "@custos/core";
import { createLogger } from "@custos/observability";
import Fastify from "fastify";
import { z } from "zod";
import { appendAuditRecord } from "./records/append.js";
import { listAuditRecords } from "./records/list.js";
import type { AuditDb } from "./db/client.js";

// Re-exported so other packages' e2e tests can boot a real instance of this
// service in-process, matching services/{identity,vault,revocation}/src/server.ts.
export { createDb } from "./db/client.js";

const reportSchema = z.object({
  agentDid: z.string().min(1),
  tool: z.string().min(1),
  action: z.string().min(1),
  dataCategories: z.array(z.string()),
  policy: z.object({ rule: z.string().min(1), decision: z.enum(["allow", "deny"]) }),
  reason: z.string().min(1).optional(),
});

/**
 * The append-only audit trail (build plan Phase 4). Its own `did:web`
 * signing identity — same pattern as the revocation service — is published
 * at `/.well-known/did.json`, so a pulled record verifies independently of
 * whichever service reported it; the audit service is the one attesting to
 * "this happened", not the vault or any connector.
 */
export async function buildServer(options: {
  readonly db: AuditDb;
  /** Required, no default: `POST /records` is never open (ADR 0008). */
  readonly controlPlaneAuth: ControlPlaneGuard;
  readonly didDomain?: string;
  readonly keyProvider?: KeyProvider;
  readonly clock?: { now(): Date };
}): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({ loggerInstance: createLogger({ level: "silent" }) });
  const { db } = options;
  const keyProvider = options.keyProvider ?? createLocalKeyProvider();
  const domain = options.didDomain ?? "localhost:4004";
  const clock = options.clock ?? { now: () => new Date() };

  const { keyId, publicKey } = await keyProvider.createKeyPair();
  const didDocument = buildDidWebDocument({ domain, publicKey });
  const signer = { sign: (data: Uint8Array) => keyProvider.sign(keyId, data) };

  app.get("/health", async () => ({ status: "ok", service: "audit" }));

  // The key every pulled record is verified against.
  app.get("/.well-known/did.json", async () => didDocument);

  // Called by the vault (and, later, any other service) to report one
  // action outcome. Deliberately fire-and-forget from the caller's side
  // (CLAUDE.md section 3) — this endpoint itself responds normally. Not
  // signed here — see the doc comment on `auditRecords` in ./db/schema.js.
  // Service keys only: this service signs whatever it stores as genuine, so
  // an open endpoint would let anyone forge evidence (ADR 0008).
  const recordsGuard = requireScope({ ...options.controlPlaneAuth, scope: "audit:write" });
  app.post("/records", { preHandler: recordsGuard }, async (request, reply) => {
    const body = reportSchema.safeParse(request.body);
    if (!body.success) {
      reply.code(400);
      return { error: "INVALID_INPUT" };
    }
    await appendAuditRecord({ db, event: body.data, now: clock.now() });
    reply.code(201);
    return { stored: true };
  });

  // Pulls the verifiable log — every record for one agent, or every record
  // at all. Each entry is freshly signed against the DID document above; the
  // caller verifies it independently.
  app.get("/records", async (request, reply) => {
    // A same-origin restriction here would only give a false sense of
    // control — every record it returns is independently verifiable
    // against the DID document above, so trusting the origin adds nothing.
    // This lets Phase 5's dashboard (apps/dashboard) read it directly from
    // the browser without a proxy.
    reply.header("access-control-allow-origin", "*");
    const query = request.query as { readonly agentId?: string };
    const result = await listAuditRecords({ db, signer, agentDid: query.agentId });
    if (!result.ok) {
      reply.code(502);
      return { error: result.error };
    }
    return { records: result.value };
  });

  return app;
}

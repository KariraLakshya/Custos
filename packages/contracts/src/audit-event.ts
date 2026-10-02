import { z } from "zod";

/** The operator or service behind a control-plane action (ADR 0008 §7). */
export const auditPrincipalSchema = z.object({
  kind: z.enum(["operator", "service"]),
  id: z.string().min(1).max(64),
  name: z.string().min(1).max(100),
});

/**
 * What a service reports to the audit service's `POST /records`. An agent
 * action names the agent (and usually a tool); a control-plane action names
 * the principal that made it. Every event names at least one actor, the same
 * rule `@custos/core`'s `AuditRecord` enforces when a record is verified.
 */
export const auditEventSchema = z
  .object({
    agentDid: z.string().min(1).max(512).optional(),
    principal: auditPrincipalSchema.optional(),
    tool: z.string().min(1).max(128).optional(),
    action: z.string().min(1).max(128),
    dataCategories: z.array(z.string().max(128)).max(64),
    policy: z.object({ rule: z.string().min(1).max(256), decision: z.enum(["allow", "deny"]) }),
    reason: z.string().min(1).max(1024).optional(),
  })
  .refine((event) => event.agentDid !== undefined || event.principal !== undefined, {
    message: "an audit event must name an agent or a principal",
  });

export type AuditPrincipal = z.infer<typeof auditPrincipalSchema>;
/** Read-only where callers hold read-only data (a connector's `dataCategories`). */
export type AuditEvent = Omit<z.infer<typeof auditEventSchema>, "dataCategories"> & {
  readonly dataCategories: readonly string[];
};

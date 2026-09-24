import { err, ok, type Result } from "@custos/contracts";
import { z } from "zod";

/**
 * The agent's identity credential, treated as opaque by the SDK: it is sent
 * to the vault verbatim and the vault verifies it. It must never be reshaped
 * — the signature covers every field — so it is validated as a loose object.
 * Typed structurally (no index signature) so a fully typed credential, such
 * as `@custos/core`'s `SignedCredential`, is accepted as-is.
 */
export type AgentCredential = { readonly issuer: string };

/** Plain, JSON-serialisable data — persist it and hand it to the agent's own process. */
export interface Agent {
  readonly id: string;
  readonly did: string;
  readonly credential: AgentCredential;
}

export interface CustosConfig {
  readonly identityUrl: string;
  readonly vaultUrl: string;
  readonly revocationUrl: string;
}

/**
 * Why a tool call did not go through. `stage` says which request was refused:
 * `token` (identity, allowlist, or revocation check at issuance) or `call`
 * (token expiry/revocation re-checked on the hot path, or the tool failed).
 * `code` is the vault's error code, e.g. `POLICY_DENIED`, `AGENT_REVOKED`,
 * `INVALID_TOKEN`; `UNKNOWN` if the response carried none.
 */
export interface CallDenied {
  readonly stage: "token" | "call";
  readonly status: number;
  readonly code: string;
  readonly detail: unknown;
}

export interface ToolConnection {
  readonly tool: string;
  call(action: string, input?: unknown): Promise<Result<unknown, CallDenied>>;
}

export interface GrantResult {
  readonly agentId: string;
  readonly tool: string;
}

export interface DeprovisionResult {
  readonly agentId: string;
  readonly agentDid: string;
  readonly statusListIndex: number;
  readonly revokedAt: string;
  readonly alreadyRevoked: boolean;
  readonly broadcast: { readonly delivered: number; readonly failed: readonly string[] };
}

export interface Custos {
  /** Registers a new agent: keypair, did:web document, and signed identity credential. */
  register(): Promise<Agent>;
  /** Operator action: allowlists `tool` for `agent`. Without it every call is denied. */
  grant(agent: Pick<Agent, "did">, tool: string): Promise<GrantResult>;
  /** Binds an agent to a tool. No network until `call`. */
  connect(agent: Pick<Agent, "credential">, tool: string): ToolConnection;
  /** Revokes the agent everywhere — every tool it can reach cuts it off. */
  deprovision(
    agent: Pick<Agent, "id">,
    options?: { readonly reason?: string },
  ): Promise<DeprovisionResult>;
}

const agentSchema = z.object({
  id: z.string().min(1),
  did: z.string().min(1),
  credential: z.looseObject({ issuer: z.string().min(1) }),
});
const tokenSchema = z.object({ token: z.string().min(1) });
const callSchema = z.object({ result: z.unknown() });
const grantSchema = z.object({ agentId: z.string(), tool: z.string() });
const deprovisionSchema = z.object({
  agentId: z.string(),
  agentDid: z.string(),
  statusListIndex: z.number(),
  revokedAt: z.string(),
  alreadyRevoked: z.boolean(),
  broadcast: z.object({ delivered: z.number(), failed: z.array(z.string()) }),
});

interface JsonResponse {
  readonly status: number;
  readonly ok: boolean;
  readonly body: unknown;
}

async function postJson(url: URL, body?: unknown): Promise<JsonResponse> {
  const response = await fetch(url, {
    method: "POST",
    ...(body === undefined
      ? {}
      : { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
  });
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = text === "" ? undefined : JSON.parse(text);
  } catch {
    parsed = text;
  }
  return { status: response.status, ok: response.ok, body: parsed };
}

/** The vault answers `{ error: "CODE" }` or `{ error: { code: "CODE", ... } }`. */
function errorCode(body: unknown): string {
  if (typeof body !== "object" || body === null || !("error" in body)) return "UNKNOWN";
  const { error } = body;
  if (typeof error === "string") return error;
  if (typeof error === "object" && error !== null && "code" in error) {
    return typeof error.code === "string" ? error.code : "UNKNOWN";
  }
  return "UNKNOWN";
}

function expectOk(what: string, service: string, response: JsonResponse): void {
  if (!response.ok) {
    throw new Error(
      `${what} failed: ${service} returned ${response.status} — ${JSON.stringify(response.body)}`,
    );
  }
}

function parseOrThrow<T>(what: string, schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new Error(`${what} failed: unexpected response shape — ${parsed.error.message}`);
  }
  return parsed.data;
}

/**
 * Control-plane operations (`register`, `grant`, `deprovision`) throw on
 * failure — they are operator actions, and a failure is an infrastructure
 * problem to surface. `call` returns a Result instead: a denial is an
 * expected, security-meaningful outcome, not an exception (CLAUDE.md §7).
 * It still throws on transport failure or a malformed success response —
 * nothing counts as allowed unless the vault's answer validates.
 */
export function createCustos(config: CustosConfig): Custos {
  // Fail at construction on a malformed URL, not at first request.
  const identityUrl = new URL(config.identityUrl);
  const vaultUrl = new URL(config.vaultUrl);
  const revocationUrl = new URL(config.revocationUrl);

  return {
    async register() {
      const response = await postJson(new URL("/agents", identityUrl));
      expectOk("register", "identity service", response);
      return parseOrThrow("register", agentSchema, response.body);
    },

    async grant(agent, tool) {
      const response = await postJson(new URL("/policies", vaultUrl), {
        agentId: agent.did,
        tool,
      });
      expectOk("grant", "vault", response);
      return parseOrThrow("grant", grantSchema, response.body);
    },

    connect(agent, tool) {
      return {
        tool,
        // A fresh scoped token per call: tokens are bound to one action and
        // live 60s, and the agent never holds anything longer-lived.
        async call(action, input) {
          const tokenResponse = await postJson(new URL("/tokens", vaultUrl), {
            tool,
            action,
            credential: agent.credential,
          });
          if (!tokenResponse.ok) {
            return err({
              stage: "token",
              status: tokenResponse.status,
              code: errorCode(tokenResponse.body),
              detail: tokenResponse.body,
            });
          }
          const { token } = parseOrThrow("token request", tokenSchema, tokenResponse.body);

          const callResponse = await postJson(new URL("/call", vaultUrl), {
            token,
            action,
            input,
          });
          if (!callResponse.ok) {
            return err({
              stage: "call",
              status: callResponse.status,
              code: errorCode(callResponse.body),
              detail: callResponse.body,
            });
          }
          return ok(parseOrThrow("call", callSchema, callResponse.body).result);
        },
      };
    },

    async deprovision(agent, options) {
      const reason = options?.reason;
      const response = await postJson(
        new URL("/revocations", revocationUrl),
        reason === undefined ? { agentId: agent.id } : { agentId: agent.id, reason },
      );
      expectOk("deprovision", "revocation service", response);
      return parseOrThrow("deprovision", deprovisionSchema, response.body);
    },
  };
}

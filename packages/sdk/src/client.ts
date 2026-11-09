import { err, ok, type Result } from "@custos/contracts";
import {
  buildHandOff,
  buildRegistrationRequest,
  buildTokenRequestProof,
  didWebFromDomain,
  type DelegatedGrant,
} from "@custos/core/possession";
import { z } from "zod";

/**
 * The agent's identity credential, treated as opaque by the SDK: it is sent
 * to the vault verbatim and the vault verifies it. It must never be reshaped
 * — the signature covers every field — so it is validated as a loose object.
 * Typed structurally (no index signature) so a fully typed credential, such
 * as `@custos/core`'s `SignedCredential`, is accepted as-is.
 */
export type AgentCredential = { readonly issuer: string };

/**
 * Plain, JSON-serialisable data — persist it and hand it to the agent's own
 * process. `secretKey` is the agent's private key: generated here, never sent
 * anywhere, and the only thing that lets the agent prove it is itself. Store
 * it like any private key (ADR 0007 decision 1).
 */
export interface Agent {
  readonly id: string;
  readonly did: string;
  readonly credential: AgentCredential;
  /** Hex-encoded 32-byte Ed25519 private key. Secret. */
  readonly secretKey: string;
}

export interface CustosConfig {
  readonly identityUrl: string;
  readonly vaultUrl: string;
  readonly revocationUrl: string;
  /**
   * An operator API key (`custos_operator_…`, ADR 0008), needed by
   * `register`, `grant` and `deprovision`. An agent-only process that just
   * calls tools through `connect` doesn't need one and shouldn't hold one.
   */
  readonly operatorKey?: string;
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

/**
 * Permission one agent passes to another (ADR 0020): signed hand-offs from
 * the first delegator down, with each delegator's credential. Plain JSON, not
 * a secret: it is bound to the receiving agent, who must still prove it holds
 * its own key. Give it to the receiving agent, which passes it to `connect`.
 */
export interface Delegation {
  readonly handOffs: readonly string[];
  readonly credentials: readonly AgentCredential[];
}

/** How long a hand-off lives by default: 10 minutes, within any vault's default limit of 1 hour. */
export const DEFAULT_DELEGATION_TTL_SECONDS = 600;

export interface DelegateOptions {
  /** The receiving agent's DID. */
  readonly to: string;
  /** What it may do: each tool with the actions allowed on it. */
  readonly grants: readonly DelegatedGrant[];
  /** Default {@link DEFAULT_DELEGATION_TTL_SECONDS}; never past the delegation it extends. */
  readonly ttlSeconds?: number;
  /**
   * How many more times it may be passed on. Default 0 for a first hand-off
   * (the receiver may not pass it on); one less than the parent's when
   * extending one.
   */
  readonly depth?: number;
  /** A delegation this agent received and is passing on, narrowed. */
  readonly extending?: Delegation;
}

export interface Custos {
  /**
   * Registers a new agent: generates its keypair locally, proves possession
   * of it to the identity service, and returns the issued credential together
   * with the private key, which never left this process.
   */
  register(): Promise<Agent>;
  /** Operator action: allowlists `tool` for `agent`. Without it every call is denied. */
  grant(agent: Pick<Agent, "did">, tool: string): Promise<GrantResult>;
  /**
   * Binds an agent to a tool. No network until `call`. Needs the agent's
   * private key: every token request proves possession of it (ADR 0007).
   */
  connect(
    agent: Pick<Agent, "credential" | "secretKey">,
    tool: string,
    options?: { readonly delegation?: Delegation },
  ): ToolConnection;
  /**
   * Lets `agent` pass some of what it may do to another agent (ADR 0020),
   * signed here with its own key. Local only: nothing is sent anywhere, and
   * Custos first sees it when the receiver uses it. Throws on a hand-off the
   * vault would refuse anyway (widening, passing on what may not be).
   */
  delegate(
    agent: Pick<Agent, "did" | "credential" | "secretKey">,
    options: DelegateOptions,
  ): Delegation;
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

async function postJson(url: URL, body?: unknown, operatorKey?: string): Promise<JsonResponse> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (operatorKey !== undefined) headers.authorization = `Bearer ${operatorKey}`;
  const response = await fetch(url, {
    method: "POST",
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
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

interface ParentClaims {
  readonly sub: string;
  readonly grants: readonly DelegatedGrant[];
  readonly depth: number;
  readonly exp: number;
}

/** The claims of the hand-off a delegation ends with; only read here, the vault verifies it. */
function lastHandOffClaims(delegation: Delegation): ParentClaims {
  const last = delegation.handOffs[delegation.handOffs.length - 1];
  try {
    const claims = JSON.parse(
      Buffer.from(last?.split(".")[0] ?? "", "base64url").toString("utf8"),
    ) as ParentClaims;
    if (typeof claims.sub === "string" && Array.isArray(claims.grants)) return claims;
  } catch {
    // reported below
  }
  throw new Error("delegate: the delegation being extended is not a readable hand-off chain");
}

/** Every tool and action in `grants` is within `parent`'s. */
function narrows(grants: readonly DelegatedGrant[], parent: readonly DelegatedGrant[]): boolean {
  return grants.every((grant) => {
    const held = parent.find((p) => p.tool === grant.tool);
    return held !== undefined && grant.actions.every((action) => held.actions.includes(action));
  });
}

/** Programmer error, not a denial: a key that isn't 32 bytes of hex never reaches the vault. */
function parseSecretKey(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    throw new Error("agent secretKey must be 64 hex characters (32 bytes)");
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
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

  /** Programmer error: an operator action with no operator key never leaves the process. */
  function operatorKey(what: string): string {
    if (config.operatorKey === undefined) {
      throw new Error(`${what} needs an operator key: pass operatorKey to createCustos`);
    }
    return config.operatorKey;
  }

  return {
    async register() {
      const key = operatorKey("register");
      const request = await buildRegistrationRequest({
        // The proof names the identity service it is for: its did:web DID,
        // derived from the URL it is reached at.
        audience: didWebFromDomain(identityUrl.host),
        now: new Date(),
      });
      const response = await postJson(new URL("/agents", identityUrl), request.body, key);
      expectOk("register", "identity service", response);
      const registered = parseOrThrow("register", agentSchema, response.body);
      return { ...registered, secretKey: Buffer.from(request.secretKey).toString("hex") };
    },

    async grant(agent, tool) {
      const response = await postJson(
        new URL("/policies", vaultUrl),
        { agentId: agent.did, tool },
        operatorKey("grant"),
      );
      expectOk("grant", "vault", response);
      return parseOrThrow("grant", grantSchema, response.body);
    },

    delegate(agent, options) {
      const now = new Date();
      const ttlSeconds = options.ttlSeconds ?? DEFAULT_DELEGATION_TTL_SECONDS;
      const secretKey = parseSecretKey(agent.secretKey);
      if (options.extending === undefined) {
        const handOff = buildHandOff({
          from: agent.did,
          to: options.to,
          grants: options.grants,
          depth: options.depth ?? 0,
          now,
          ttlSeconds,
          secretKey,
        });
        return { handOffs: [handOff], credentials: [agent.credential] };
      }
      const parent = lastHandOffClaims(options.extending);
      if (parent.sub !== agent.did) {
        throw new Error("delegate: only the agent a delegation was given to can pass it on");
      }
      if (parent.depth < 1) {
        throw new Error("delegate: this delegation may not be passed on (its depth is 0)");
      }
      const depth = options.depth ?? parent.depth - 1;
      if (depth >= parent.depth) {
        throw new Error(`delegate: depth must be less than the parent's (${parent.depth})`);
      }
      if (!narrows(options.grants, parent.grants)) {
        throw new Error("delegate: can only pass on tools and actions it was itself given");
      }
      // Never past the hand-off it extends.
      const remaining = parent.exp - Math.floor(now.getTime() / 1000);
      if (remaining <= 0) throw new Error("delegate: the delegation being extended has expired");
      const handOff = buildHandOff({
        from: agent.did,
        to: options.to,
        grants: options.grants,
        depth,
        previous: options.extending.handOffs[options.extending.handOffs.length - 1]!,
        now,
        ttlSeconds: Math.min(ttlSeconds, remaining),
        secretKey,
      });
      return {
        handOffs: [...options.extending.handOffs, handOff],
        credentials: [...options.extending.credentials, agent.credential],
      };
    },

    connect(agent, tool, options) {
      const delegation = options?.delegation;
      return {
        tool,
        // A fresh scoped token per call: tokens are bound to one action and
        // live 60s, and the agent never holds anything longer-lived.
        async call(action, input) {
          const tokensUrl = new URL("/tokens", vaultUrl);
          // A fresh, single-use proof per request, addressed to this vault.
          // Bound to this tool and action (ADR 0015): a captured request
          // cannot be spent on another tool the agent is granted.
          const proof = await buildTokenRequestProof({
            audience: tokensUrl.href,
            secretKey: parseSecretKey(agent.secretKey),
            now: new Date(),
            request: { tool, action },
          });
          const tokenResponse = await postJson(tokensUrl, {
            tool,
            action,
            credential: agent.credential,
            proof,
            // Sent with every request: each call gets a fresh token.
            ...(delegation === undefined ? {} : { delegation }),
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
        operatorKey("deprovision"),
      );
      expectOk("deprovision", "revocation service", response);
      return parseOrThrow("deprovision", deprovisionSchema, response.body);
    },
  };
}

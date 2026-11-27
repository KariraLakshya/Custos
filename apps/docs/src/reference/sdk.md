# SDK

`@custos/sdk` is the developer-facing client. It is a private workspace package, not on npm yet; use it from inside the repository. Everything below is exported from `packages/sdk/src/index.ts`.

```ts
import { createCustos, CustosError, DEFAULT_DELEGATION_TTL_SECONDS } from "@custos/sdk";
```

## `createCustos(config)`

```ts
function createCustos(config: CustosConfig): Custos;

interface CustosConfig {
  readonly identityUrl: string;
  readonly vaultUrl: string;
  readonly revocationUrl: string;
  /** An operator API key (custos_operator_…), needed by register, grant and deprovision. */
  readonly operatorKey?: string;
}
```

The three URLs are parsed at once, so a malformed URL throws here rather than at the first request. Each call contacts only the service it needs. An agent-only process that just calls tools should not be given `operatorKey`.

## `custos.register(options?)`

```ts
register(options?: { readonly name?: string }): Promise<Agent>;
```

Operator action (`agents:register`). Generates the agent's Ed25519 key pair locally, proves possession of it to the identity service, and returns the issued credential together with the private key, which never left this process. `name` is shown beside the agent; it is not unique and does not identify it. Throws if no `operatorKey` was configured, and `CustosError` if the service refuses.

## `custos.grant(agent, tool)`

```ts
grant(agent: Pick<Agent, "did">, tool: string): Promise<GrantResult>;
```

Operator action (`policies:write`). Allowlists `tool` for the agent. Without it every call is denied.

## `custos.connect(agent, tool, options?)`

```ts
connect(
  agent: Pick<Agent, "credential" | "secretKey">,
  tool: string,
  options?: { readonly delegation?: Delegation },
): ToolConnection;

interface ToolConnection {
  readonly tool: string;
  call(action: string, input?: unknown): Promise<Result<unknown, CallDenied>>;
}
```

Binds an agent to a tool; nothing is sent until `call`. Each `call` makes a fresh, single-use proof of possession bound to this tool and action, gets a fresh 60-second token, and calls the tool. Pass `delegation` to act on permission another agent passed on.

`call` **returns** a refusal rather than throwing it:

```ts
type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };

interface CallDenied {
  readonly stage: "token" | "call"; // which request was refused
  readonly status: number; // HTTP status
  readonly code: string; // e.g. POLICY_DENIED, AGENT_REVOKED, INVALID_TOKEN; UNKNOWN if none
  readonly detail: unknown; // the response body
}
```

It throws only when a service can't be reached (`CustosError` with code `SERVICE_UNREACHABLE`) or sends a success response that doesn't validate. Nothing counts as allowed unless the vault's answer validates. A `secretKey` that isn't 64 hex characters throws before anything is sent.

## `custos.delegate(agent, options)` {#delegate}

```ts
delegate(agent: Pick<Agent, "did" | "credential" | "secretKey">, options: DelegateOptions): Delegation;

interface DelegateOptions {
  readonly to: string;                         // the receiving agent's DID
  readonly grants: readonly DelegatedGrant[];  // [{ tool, actions: [...] }]
  readonly ttlSeconds?: number;                // default DEFAULT_DELEGATION_TTL_SECONDS (600); never past what it extends
  readonly depth?: number;                     // default 0 for a first hand-off; one less than the parent's when extending
  readonly extending?: Delegation;             // a delegation this agent received and is passing on
}

interface Delegation {
  readonly handOffs: readonly string[];
  readonly credentials: readonly AgentCredential[];
}
```

Signs a hand-off locally with the agent's key. Nothing is sent anywhere; Custos first sees it when the receiver uses it with `connect(..., { delegation })`. Throws on a hand-off the vault would refuse anyway: extending a delegation made out to another agent, one whose depth is 0, one that has expired, a depth not less than the parent's, or tools and actions the agent was not itself given.

## `custos.deprovision(agent, options?)`

```ts
deprovision(agent: Pick<Agent, "id">, options?: { readonly reason?: string }): Promise<DeprovisionResult>;
```

Operator action (`agents:revoke`). Revokes the agent everywhere. The CLI calls this command `revoke`.

## Operator reads

```ts
findAgent(agent: { readonly id: string } | { readonly did: string }): Promise<RegisteredAgent | null>;
listGrants(agent: Pick<Agent, "did">): Promise<readonly Grant[]>;
findRevocation(agent: Pick<Agent, "did">): Promise<Revocation | null>;
```

Each needs an operator key with its read scope: `agents:read`, `policies:read` and `revocations:read`. `findAgent` returns `null` for an agent identity doesn't know. `listGrants` follows every page and throws rather than return part of the list. `findRevocation` returns `null` when the agent isn't revoked, and throws if any entry in the list can't be read, rather than answer "not revoked" from a list it couldn't fully read. `custos status` is built on these. The types `RegisteredAgent`, `Grant`, `Revocation` and `Principal` are exported from `@custos/sdk`.

## Types

```ts
interface Agent {
  readonly id: string;
  readonly did: string;
  readonly credential: AgentCredential;
  readonly name?: string | null; // null when none was given; absent when loaded from a credential file
  readonly secretKey: string; // hex-encoded 32-byte Ed25519 private key. Secret.
}

type AgentCredential = { readonly issuer: string }; // opaque: sent verbatim, never reshaped

interface GrantResult {
  readonly agentId: string;
  readonly tool: string;
}

interface DeprovisionResult {
  readonly agentId: string;
  readonly agentDid: string;
  readonly statusListIndex: number;
  readonly revokedAt: string;
  readonly alreadyRevoked: boolean;
  readonly broadcast: { readonly delivered: number; readonly failed: readonly string[] };
}
```

`DelegatedGrant` is `{ tool: string; actions: string[] }`, re-exported from `@custos/core/possession`. `Result` is re-exported from `@custos/contracts`.

## `CustosError`

```ts
class CustosError extends Error {
  readonly code: string; // the service's code (UNAUTHORIZED, UNKNOWN_AGENT, …) or SERVICE_UNREACHABLE
  readonly reason: string | undefined; // the finer reason, when the service sent one
  readonly status: number | undefined; // HTTP status; undefined when no service answered
}
```

Thrown by `register`, `grant` and `deprovision` when a service refuses, and by any call when a service does not answer. Look a code up with `refusalFor(code, reason)` from `@custos/contracts` for its meaning and next step ([Refusal codes](/reference/refusals)).

## Other exports

- `DEFAULT_DELEGATION_TTL_SECONDS`: `600`.
- `SDK_VERSION`: `"0.0.0"`.

export const SDK_VERSION = "0.0.0";

export {
  createCustos,
  CustosError,
  DEFAULT_DELEGATION_TTL_SECONDS,
  type Agent,
  type AgentCredential,
  type CallDenied,
  type Custos,
  type CustosConfig,
  type DelegateOptions,
  type Delegation,
  type DeprovisionResult,
  type Grant,
  type GrantResult,
  type Principal,
  type RegisteredAgent,
  type Revocation,
  type ToolConnection,
} from "./client.js";
export type { Result } from "@custos/contracts";
export type { DelegatedGrant } from "@custos/core/possession";

export const SDK_VERSION = "0.0.0";

export {
  createCustos,
  DEFAULT_DELEGATION_TTL_SECONDS,
  type Agent,
  type AgentCredential,
  type CallDenied,
  type Custos,
  type CustosConfig,
  type DelegateOptions,
  type Delegation,
  type DeprovisionResult,
  type GrantResult,
  type ToolConnection,
} from "./client.js";
export type { Result } from "@custos/contracts";
export type { DelegatedGrant } from "@custos/core/possession";

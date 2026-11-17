import { z } from "zod";

/**
 * An agent's display name, given at registration (ADR 0022 §2). Names are
 * not unique and never pick an agent: commands take an id or DID. Shown
 * only, so they are kept to plain characters that cannot break a terminal
 * line or a page.
 */
export const AGENT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/;
export const AGENT_NAME_MAX_LENGTH = 64;

export const agentNameSchema = z
  .string()
  .min(1)
  .max(AGENT_NAME_MAX_LENGTH)
  .regex(AGENT_NAME_PATTERN);

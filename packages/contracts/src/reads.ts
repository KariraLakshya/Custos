import { z } from "zod";

/**
 * Query values shared by the guarded list reads (ADR 0022 §1, §2): identity
 * `GET /agents` and vault `GET /policies`. Query strings are untrusted input,
 * so each value is a bounded string checked here, before it reaches a query.
 */

/** The longest DID a read accepts; the same bound the delegation verifier uses. */
export const DID_MAX_LENGTH = 512;

/**
 * A DID in a query: `did:<method>:<id>`, plain characters only. It shapes the
 * input; whether the DID names anything is the query's answer (an empty list).
 */
export const didSchema = z
  .string()
  .min(1)
  .max(DID_MAX_LENGTH)
  .regex(/^did:[a-z0-9]+:[A-Za-z0-9._%:-]+$/);

export const PAGE_LIMIT_DEFAULT = 50;
export const PAGE_LIMIT_MAX = 200;

/** `?limit=`: digits only, 1 to `PAGE_LIMIT_MAX`. Anything else is refused, not clamped. */
export const pageLimitSchema = z
  .string()
  .regex(/^[1-9][0-9]{0,3}$/)
  .transform(Number)
  .refine((limit) => limit <= PAGE_LIMIT_MAX);

import { sha256 } from "@noble/hashes/sha2.js";
import { sign } from "../crypto/ed25519.js";
import { isBoundRequest } from "../proof/possession.js";

/**
 * A hand-off (ADR 0020 §2): one agent passing part of what it may do to
 * another, signed with the delegating agent's own key. Same compact envelope
 * family as tokens, proofs, tombstones and seals:
 * `base64url(JSON claims).base64url(Ed25519 signature over the first part)`.
 */
export const HAND_OFF_TYPE = "custos-delegation+v1";

/** One tool and the actions on it that a hand-off passes on. */
export interface DelegatedGrant {
  readonly tool: string;
  readonly actions: readonly string[];
}

export interface HandOffClaims {
  readonly typ: typeof HAND_OFF_TYPE;
  /** The delegating agent's DID. */
  readonly iss: string;
  /** The agent receiving the authority. */
  readonly sub: string;
  readonly grants: readonly DelegatedGrant[];
  /** How many further hand-offs are allowed below this one. */
  readonly depth: number;
  /** `handOffHash` of the hand-off this one extends; null for the first. */
  readonly prev: string | null;
  /** Unix seconds. */
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
}

// Bounds on what one hand-off may name, so a verifier's work is bounded too.
export const MAX_GRANTS_PER_HAND_OFF = 16;
export const MAX_ACTIONS_PER_GRANT = 32;

/** Non-empty, bounded grants whose tools and actions are 1–128 characters. */
export function isDelegatedGrantList(value: unknown): value is readonly DelegatedGrant[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_GRANTS_PER_HAND_OFF) {
    return false;
  }
  return value.every((grant: unknown) => {
    if (typeof grant !== "object" || grant === null) return false;
    const { tool, actions } = grant as Record<string, unknown>;
    return (
      Array.isArray(actions) &&
      actions.length > 0 &&
      actions.length <= MAX_ACTIONS_PER_GRANT &&
      actions.every((action: unknown) => isBoundRequest({ tool, action }))
    );
  });
}

/**
 * The value a following hand-off puts in `prev`: SHA-256 of this hand-off's
 * exact compact form, base64url. It covers the signature too, so the next
 * link names one specific signed hand-off, not just its claims.
 */
export function handOffHash(handOff: string): string {
  return Buffer.from(sha256(new TextEncoder().encode(handOff))).toString("base64url");
}

/**
 * Signs a hand-off with the delegating agent's own key (ADR 0020 §2). Runs
 * where the key is, on the agent's side: no control-plane call. Throws on
 * malformed grants, a programmer error; the verifier enforces everything else.
 */
export function buildHandOff(params: {
  readonly from: string;
  readonly to: string;
  readonly grants: readonly DelegatedGrant[];
  readonly depth: number;
  /** The hand-off this one extends, as received; omitted for the first. */
  readonly previous?: string;
  readonly now: Date;
  readonly ttlSeconds: number;
  readonly secretKey: Uint8Array;
  readonly jti?: string;
}): string {
  if (!isDelegatedGrantList(params.grants)) {
    throw new Error("hand-off: grants must be 1 to 16 tools, each with 1 to 32 actions");
  }
  if (!Number.isSafeInteger(params.depth) || params.depth < 0) {
    throw new Error("hand-off: depth must be a whole number of at least 0");
  }
  if (!Number.isSafeInteger(params.ttlSeconds) || params.ttlSeconds <= 0) {
    throw new Error("hand-off: ttlSeconds must be a positive whole number");
  }
  const iat = Math.floor(params.now.getTime() / 1000);
  const claims: HandOffClaims = {
    typ: HAND_OFF_TYPE,
    iss: params.from,
    sub: params.to,
    grants: params.grants.map(({ tool, actions }) => ({ tool, actions: [...actions] })),
    depth: params.depth,
    prev: params.previous === undefined ? null : handOffHash(params.previous),
    iat,
    exp: iat + params.ttlSeconds,
    jti: params.jti ?? crypto.randomUUID(),
  };
  const encoded = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const signature = sign(Buffer.from(encoded, "utf8"), params.secretKey);
  return `${encoded}.${Buffer.from(signature).toString("base64url")}`;
}

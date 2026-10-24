import { generateKeyPair, sign, verify } from "../crypto/ed25519.js";
import { publicKeyToMultibase } from "../did/did-web.js";
import { err, ok, type Result } from "../result.js";

/**
 * Proof of possession (ADR 0007): a short signed statement, made with an
 * agent's own private key, that the caller holds that key right now. The
 * pattern follows RFC 9449 (DPoP) — typed, audience-bound, time-bound, with
 * a unique id — encoded in the same compact envelope family as scoped tokens
 * (ADR 0003): `base64url(JSON claims).base64url(Ed25519 signature)`.
 *
 * One agent key signs more than one kind of proof, so every proof carries a
 * `typ` the verifier must match: a captured registration proof must never be
 * accepted where a token-request proof is expected.
 */
export const REGISTRATION_PROOF_TYPE = "custos-registration-proof";
/** A token request to the vault (ADR 0007 decision 3); `aud` is the vault's `/tokens` URL. */
export const TOKEN_REQUEST_PROOF_TYPE = "custos-token-request-proof";

/**
 * A call from an agent of one organisation to a service of another (ADR 0014);
 * `aud` is the receiving organisation's own identifier, never the vault's URL,
 * so a proof made for one cannot be replayed at the other.
 */
export const FOREIGN_CALL_PROOF_TYPE = "custos-foreign-call-proof";

/**
 * What a request-bound proof is for (ADR 0015): the tool and the action the
 * receiver is about to run or issue a token for. Signed into the proof, so a
 * proof captured in flight cannot be spent on a different tool or action.
 */
export interface BoundRequest {
  readonly tool: string;
  readonly action: string;
}

/**
 * Proof types that must name their request (ADR 0015): a call into another
 * organisation, and a token request to the vault. The general verifier
 * refuses these, so their binding can never be skipped.
 */
const REQUEST_BOUND_TYPES: ReadonlySet<string> = new Set([
  FOREIGN_CALL_PROOF_TYPE,
  TOKEN_REQUEST_PROOF_TYPE,
]);

// The audit schema's bound for `tool` and `action`, so a bound request can
// always be recorded as given.
const MAX_REQUEST_FIELD_LENGTH = 128;

function isRequestField(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_REQUEST_FIELD_LENGTH;
}

/** A tool and an action that are non-empty strings of at most 128 characters. */
export function isBoundRequest(value: unknown): value is BoundRequest {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  return isRequestField(request.tool) && isRequestField(request.action);
}

export interface PossessionProofClaims {
  /** Which kind of proof this is; see `REGISTRATION_PROOF_TYPE`. */
  readonly typ: string;
  /** The DID of the service this proof is meant for. */
  readonly aud: string;
  /** Issued-at, in whole seconds since the epoch. */
  readonly iat: number;
  /** Unique id, so a verifier can refuse a replayed proof. */
  readonly jti: string;
}

export type IssuePossessionProofError = {
  readonly code: "SIGNING_FAILED";
  readonly reason: string;
};

export type VerifyPossessionProofError =
  | { readonly code: "MALFORMED_PROOF"; readonly reason: string }
  | { readonly code: "SIGNATURE_INVALID" }
  | { readonly code: "WRONG_TYPE" }
  | { readonly code: "WRONG_AUDIENCE" }
  | { readonly code: "STALE" }
  /** A request-bound proof made for a different tool or action (ADR 0015). */
  | { readonly code: "WRONG_REQUEST" };

// Real proofs are a few hundred bytes; refuse anything far larger before parsing.
const MAX_PROOF_LENGTH = 4096;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isPossessionProofClaims(value: unknown): value is PossessionProofClaims {
  if (typeof value !== "object" || value === null) return false;
  const claims = value as Record<string, unknown>;
  return (
    typeof claims.typ === "string" &&
    typeof claims.aud === "string" &&
    typeof claims.iat === "number" &&
    Number.isFinite(claims.iat) &&
    typeof claims.jti === "string"
  );
}

export async function issuePossessionProof(params: {
  readonly claims: PossessionProofClaims;
  readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
}): Promise<Result<string, IssuePossessionProofError>> {
  try {
    const encodedClaims = Buffer.from(JSON.stringify(params.claims), "utf8").toString("base64url");
    const signature = await params.sign(Buffer.from(encodedClaims, "utf8"));
    return ok(`${encodedClaims}.${Buffer.from(signature).toString("base64url")}`);
  } catch (error) {
    return err({ code: "SIGNING_FAILED", reason: errorMessage(error) });
  }
}

type VerifiedEnvelope = PossessionProofClaims & Readonly<Record<string, unknown>>;

function verifyEnvelope(params: {
  readonly proof: string;
  readonly publicKey: Uint8Array;
  readonly expectedType: string;
  readonly expectedAudience: string;
  readonly now: Date;
  readonly maxSkewSeconds: number;
}): Result<VerifiedEnvelope, VerifyPossessionProofError> {
  const { proof, publicKey, expectedType, expectedAudience, now, maxSkewSeconds } = params;
  if (proof.length > MAX_PROOF_LENGTH) {
    return err({ code: "MALFORMED_PROOF", reason: "proof exceeds maximum length" });
  }
  const parts = proof.split(".");
  if (parts.length !== 2) {
    return err({ code: "MALFORMED_PROOF", reason: "expected exactly one '.' separator" });
  }
  const [encodedClaims, encodedSignature] = parts as [string, string];

  let claims: VerifiedEnvelope;
  try {
    const decoded: unknown = JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8"));
    if (!isPossessionProofClaims(decoded)) {
      return err({ code: "MALFORMED_PROOF", reason: "claims missing required fields" });
    }
    claims = decoded as VerifiedEnvelope;
  } catch (error) {
    return err({ code: "MALFORMED_PROOF", reason: errorMessage(error) });
  }

  const signature = Buffer.from(encodedSignature, "base64url");
  if (!verify(signature, Buffer.from(encodedClaims, "utf8"), publicKey)) {
    return err({ code: "SIGNATURE_INVALID" });
  }
  if (claims.typ !== expectedType) return err({ code: "WRONG_TYPE" });
  if (claims.aud !== expectedAudience) return err({ code: "WRONG_AUDIENCE" });
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (Math.abs(nowSeconds - claims.iat) > maxSkewSeconds) return err({ code: "STALE" });

  return ok(claims);
}

/**
 * Verifies locally against the public key the proof claims to be made with.
 * The signature is checked before any claim is trusted; then type, audience,
 * and freshness (`|now − iat| ≤ maxSkewSeconds`, explicit configuration per
 * CLAUDE.md §3). Replay (a reused `jti`) is the caller's check — it needs
 * state this pure module does not hold.
 *
 * Refuses request-bound proofs (foreign calls, token requests): only
 * `verifyForeignCallProof` and `verifyTokenRequestProof` check their binding,
 * so it cannot be skipped by reaching for this function instead.
 */
export function verifyPossessionProof(params: {
  readonly proof: string;
  readonly publicKey: Uint8Array;
  readonly expectedType: string;
  readonly expectedAudience: string;
  readonly now: Date;
  readonly maxSkewSeconds: number;
}): Result<PossessionProofClaims, VerifyPossessionProofError> {
  if (REQUEST_BOUND_TYPES.has(params.expectedType)) {
    return err({
      code: "MALFORMED_PROOF",
      reason: "request-bound proofs are verified with their own verifier",
    });
  }
  const verified = verifyEnvelope(params);
  if (!verified.ok) return verified;
  const { typ, aud, iat, jti } = verified.value;
  return ok({ typ, aud, iat, jti });
}

function verifyBoundProof(params: {
  readonly proof: string;
  readonly publicKey: Uint8Array;
  readonly expectedType: string;
  readonly expectedAudience: string;
  readonly expectedRequest: BoundRequest;
  readonly now: Date;
  readonly maxSkewSeconds: number;
}): Result<PossessionProofClaims, VerifyPossessionProofError> {
  if (!isBoundRequest(params.expectedRequest)) {
    return err({ code: "MALFORMED_PROOF", reason: "no valid expected request to check against" });
  }
  const verified = verifyEnvelope(params);
  if (!verified.ok) return verified;
  const { tool, action } = verified.value;
  if (typeof tool !== "string" || typeof action !== "string") {
    return err({ code: "MALFORMED_PROOF", reason: "proof does not name its request" });
  }
  if (tool !== params.expectedRequest.tool || action !== params.expectedRequest.action) {
    return err({ code: "WRONG_REQUEST" });
  }
  const { typ, aud, iat, jti } = verified.value;
  return ok({ typ, aud, iat, jti });
}

/**
 * Verifies a foreign-call proof (ADR 0014, ADR 0015): everything
 * `verifyPossessionProof` checks, and then that it was made for exactly this
 * tool and action. A proof that names no request (the format before ADR 0015)
 * is refused. The request is checked before any replay bookkeeping, so a
 * proof presented for the wrong action is refused without using it up.
 */
export function verifyForeignCallProof(params: {
  readonly proof: string;
  readonly publicKey: Uint8Array;
  readonly expectedAudience: string;
  /** What the receiver is about to run, from its own routing; never from the caller. */
  readonly expectedRequest: BoundRequest;
  readonly now: Date;
  readonly maxSkewSeconds: number;
}): Result<PossessionProofClaims, VerifyPossessionProofError> {
  return verifyBoundProof({ ...params, expectedType: FOREIGN_CALL_PROOF_TYPE });
}

/**
 * Verifies the proof on a `POST /tokens` (ADR 0007 decision 3, ADR 0015):
 * everything `verifyPossessionProof` checks, and then that it was made for
 * exactly the tool and action the token is being issued for, so a captured
 * request cannot be spent on another tool the agent is granted.
 */
export function verifyTokenRequestProof(params: {
  readonly proof: string;
  readonly publicKey: Uint8Array;
  readonly expectedAudience: string;
  /** The tool and action of the token about to be issued. */
  readonly expectedRequest: BoundRequest;
  readonly now: Date;
  readonly maxSkewSeconds: number;
}): Result<PossessionProofClaims, VerifyPossessionProofError> {
  return verifyBoundProof({ ...params, expectedType: TOKEN_REQUEST_PROOF_TYPE });
}

/**
 * When a verifier may forget a proof's `jti`. `verifyPossessionProof` floors
 * `now` to whole seconds, so a proof is still accepted until just before
 * `(iat + maxSkew + 1)` s; remembering it only until `iat + maxSkew` leaves up
 * to a second in which a captured proof can be replayed.
 */
export function proofReplayExpiresAtMs(iat: number, maxSkewSeconds: number): number {
  return (iat + maxSkewSeconds + 1) * 1000;
}

export interface RegistrationRequest {
  readonly publicKey: Uint8Array;
  /** The agent's private key. Stays with the agent — never sent anywhere. */
  readonly secretKey: Uint8Array;
  /** What to POST to the identity service's `/agents`. */
  readonly body: { readonly publicKey: string; readonly proof: string };
}

/**
 * Generates the agent's keypair locally and proves possession of it to the
 * identity service (`audience`, its DID). Only the public key and the proof
 * leave this function's return value in `body`.
 */
export async function buildRegistrationRequest(params: {
  readonly audience: string;
  readonly now: Date;
  readonly jti?: string;
}): Promise<RegistrationRequest> {
  const { publicKey, secretKey } = generateKeyPair();
  const proof = await issuePossessionProof({
    claims: {
      typ: REGISTRATION_PROOF_TYPE,
      aud: params.audience,
      iat: Math.floor(params.now.getTime() / 1000),
      jti: params.jti ?? crypto.randomUUID(),
    },
    sign: async (data) => sign(data, secretKey),
  });
  // Signing with an in-memory key cannot fail short of a programmer error.
  if (!proof.ok) throw new Error(proof.error.reason);
  return {
    publicKey,
    secretKey,
    body: { publicKey: publicKeyToMultibase(publicKey), proof: proof.value },
  };
}

async function buildBoundProof(params: {
  readonly typ: string;
  readonly audience: string;
  readonly secretKey: Uint8Array;
  readonly now: Date;
  readonly request: BoundRequest;
  readonly jti?: string;
}): Promise<string> {
  if (!isBoundRequest(params.request)) {
    throw new Error("request-bound proof: tool and action must be 1 to 128 characters");
  }
  const claims: PossessionProofClaims & BoundRequest = {
    typ: params.typ,
    aud: params.audience,
    iat: Math.floor(params.now.getTime() / 1000),
    jti: params.jti ?? crypto.randomUUID(),
    tool: params.request.tool,
    action: params.request.action,
  };
  const proof = await issuePossessionProof({
    claims,
    sign: async (data) => sign(data, params.secretKey),
  });
  // Signing with an in-memory key cannot fail short of a programmer error.
  if (!proof.ok) throw new Error(proof.error.reason);
  return proof.value;
}

/**
 * Proof an agent attaches to a call into another organisation (ADR 0014):
 * made with its own key, addressed to the receiver's identifier, fresh,
 * single-use, and bound to the one tool and action it is for (ADR 0015).
 */
export function buildForeignCallProof(params: {
  readonly audience: string;
  readonly secretKey: Uint8Array;
  readonly now: Date;
  readonly request: BoundRequest;
  readonly jti?: string;
}): Promise<string> {
  return buildBoundProof({ ...params, typ: FOREIGN_CALL_PROOF_TYPE });
}

/**
 * Proof that accompanies every `POST /tokens` (ADR 0007 decision 3): made with
 * the agent's own key, addressed to the vault's `/tokens` URL, fresh,
 * single-use (the vault remembers `jti`s), and bound to the tool and action
 * of the token it asks for (ADR 0015). Without it, a copied credential gets
 * no tokens.
 */
export function buildTokenRequestProof(params: {
  readonly audience: string;
  readonly secretKey: Uint8Array;
  readonly now: Date;
  readonly request: BoundRequest;
  readonly jti?: string;
}): Promise<string> {
  return buildBoundProof({ ...params, typ: TOKEN_REQUEST_PROOF_TYPE });
}

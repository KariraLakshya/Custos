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
  | { readonly code: "STALE" };

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

/**
 * Verifies locally against the public key the proof claims to be made with.
 * The signature is checked before any claim is trusted; then type, audience,
 * and freshness (`|now − iat| ≤ maxSkewSeconds`, explicit configuration per
 * CLAUDE.md §3). Replay (a reused `jti`) is the caller's check — it needs
 * state this pure module does not hold.
 */
export function verifyPossessionProof(params: {
  readonly proof: string;
  readonly publicKey: Uint8Array;
  readonly expectedType: string;
  readonly expectedAudience: string;
  readonly now: Date;
  readonly maxSkewSeconds: number;
}): Result<PossessionProofClaims, VerifyPossessionProofError> {
  const { proof, publicKey, expectedType, expectedAudience, now, maxSkewSeconds } = params;
  if (proof.length > MAX_PROOF_LENGTH) {
    return err({ code: "MALFORMED_PROOF", reason: "proof exceeds maximum length" });
  }
  const parts = proof.split(".");
  if (parts.length !== 2) {
    return err({ code: "MALFORMED_PROOF", reason: "expected exactly one '.' separator" });
  }
  const [encodedClaims, encodedSignature] = parts as [string, string];

  let claims: PossessionProofClaims;
  try {
    const decoded: unknown = JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8"));
    if (!isPossessionProofClaims(decoded)) {
      return err({ code: "MALFORMED_PROOF", reason: "claims missing required fields" });
    }
    claims = decoded;
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

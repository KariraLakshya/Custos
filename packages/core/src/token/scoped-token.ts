import { verify } from "../crypto/ed25519.js";
import { err, ok, type Result } from "../result.js";

/**
 * A vault-issued scoped access token's claims (CLAUDE.md section 4: "tokens
 * are short-lived and scoped — default 60s TTL, bound to a specific tool and
 * action set"). `sub` is the requesting agent's did:web DID. `iat`/`exp` are
 * unix seconds, not milliseconds, to keep the encoded token short.
 */
export interface ScopedTokenClaims {
  readonly sub: string;
  readonly tool: string;
  readonly action: string;
  readonly iat: number;
  readonly exp: number;
}

/**
 * KMS-shaped signing callback, the same shape as `vc/credential.ts`'s
 * `CredentialSigner` (CLAUDE.md section 4): never exposes private key
 * material, only a signature.
 */
export interface ScopedTokenSigner {
  readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
}

export type IssueScopedTokenError = { readonly code: "SIGNING_FAILED"; readonly reason: string };

export type VerifyScopedTokenError =
  | { readonly code: "MALFORMED_TOKEN"; readonly reason: string }
  | { readonly code: "SIGNATURE_INVALID" }
  | { readonly code: "EXPIRED" };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isScopedTokenClaims(value: unknown): value is ScopedTokenClaims {
  if (typeof value !== "object" || value === null) return false;
  const claims = value as Record<string, unknown>;
  return (
    typeof claims.sub === "string" &&
    typeof claims.tool === "string" &&
    typeof claims.action === "string" &&
    typeof claims.iat === "number" &&
    typeof claims.exp === "number"
  );
}

/**
 * Issues a compact signed token: base64url(claims JSON) + "." +
 * base64url(signature over the base64url-encoded claims). A custom format
 * rather than JWT/JOSE — see docs/adr/0003-scoped-token-format.md — signed
 * via an injected `signer`, never a raw secret key.
 */
export async function issueScopedToken(params: {
  readonly claims: ScopedTokenClaims;
  readonly signer: ScopedTokenSigner;
}): Promise<Result<string, IssueScopedTokenError>> {
  try {
    const encodedClaims = Buffer.from(JSON.stringify(params.claims), "utf8").toString("base64url");
    const signature = await params.signer.sign(Buffer.from(encodedClaims, "utf8"));
    const encodedSignature = Buffer.from(signature).toString("base64url");
    return ok(`${encodedClaims}.${encodedSignature}`);
  } catch (error) {
    return err({ code: "SIGNING_FAILED", reason: errorMessage(error) });
  }
}

/**
 * Verifies a scoped token entirely locally against a caller-supplied public
 * key — no network call, no database lookup (CLAUDE.md section 3, "hot path
 * ... verification is local and offline-capable"). Fails closed: malformed
 * structure, a bad signature, and expiry are all rejected, never thrown.
 * `now` is injected rather than read from the clock (CLAUDE.md section 3).
 */
export function verifyScopedToken(params: {
  readonly token: string;
  readonly publicKey: Uint8Array;
  readonly now: Date;
}): Result<ScopedTokenClaims, VerifyScopedTokenError> {
  const { token, publicKey, now } = params;
  const parts = token.split(".");
  if (parts.length !== 2) {
    return err({ code: "MALFORMED_TOKEN", reason: "expected exactly one '.' separator" });
  }
  const [encodedClaims, encodedSignature] = parts as [string, string];

  let claims: ScopedTokenClaims;
  try {
    const decoded: unknown = JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8"));
    if (!isScopedTokenClaims(decoded)) {
      return err({ code: "MALFORMED_TOKEN", reason: "claims missing required fields" });
    }
    claims = decoded;
  } catch (error) {
    return err({ code: "MALFORMED_TOKEN", reason: errorMessage(error) });
  }

  const signature = Buffer.from(encodedSignature, "base64url");
  const signedData = Buffer.from(encodedClaims, "utf8");
  if (!verify(signature, signedData, publicKey)) {
    return err({ code: "SIGNATURE_INVALID" });
  }

  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (nowSeconds >= claims.exp) {
    return err({ code: "EXPIRED" });
  }

  return ok(claims);
}

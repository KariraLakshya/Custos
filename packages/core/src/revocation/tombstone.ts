import { verify } from "../crypto/ed25519.js";
import { err, ok, type Result } from "../result.js";

/**
 * A signed statement that one agent's credential has been revoked, pushed
 * from the revocation service to every subscriber (CLAUDE.md section 3,
 * "push, don't pull"). `agentDid` is the agent's did:web DID — the same
 * identifier a scoped token carries in `sub`, so a subscriber can match a
 * tombstone against an in-flight call without a lookup.
 *
 * `statusListIndex` ties the tombstone to its entry in the published Status
 * List 2021 credential, so a recipient can independently confirm the
 * revocation against the durable list rather than trusting the push alone.
 */
export interface RevocationTombstone {
  readonly agentDid: string;
  readonly statusListIndex: number;
  readonly revokedAt: string;
  readonly reason?: string;
}

/**
 * KMS-shaped signing callback, identical in shape to `ScopedTokenSigner`
 * (CLAUDE.md section 4): never exposes private key material.
 */
export interface TombstoneSigner {
  readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
}

export type IssueTombstoneError = { readonly code: "SIGNING_FAILED"; readonly reason: string };

export type VerifyTombstoneError =
  | { readonly code: "MALFORMED_TOMBSTONE"; readonly reason: string }
  | { readonly code: "SIGNATURE_INVALID" };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isRevocationTombstone(value: unknown): value is RevocationTombstone {
  if (typeof value !== "object" || value === null) return false;
  const claims = value as Record<string, unknown>;
  return (
    typeof claims.agentDid === "string" &&
    claims.agentDid.length > 0 &&
    typeof claims.statusListIndex === "number" &&
    Number.isInteger(claims.statusListIndex) &&
    claims.statusListIndex >= 0 &&
    typeof claims.revokedAt === "string" &&
    (claims.reason === undefined || typeof claims.reason === "string")
  );
}

/**
 * Same compact envelope as a scoped token — base64url(claims JSON) + "." +
 * base64url(signature) — for the reasons recorded in
 * docs/adr/0003-scoped-token-format.md, and so both use one verify path.
 *
 * Deliberately carries no expiry: a revocation is permanent, so a replayed
 * tombstone can only ever re-revoke an already-revoked agent, which is
 * idempotent. There is no un-revoke for a replay to undo.
 */
export async function issueRevocationTombstone(params: {
  readonly tombstone: RevocationTombstone;
  readonly signer: TombstoneSigner;
}): Promise<Result<string, IssueTombstoneError>> {
  try {
    const encodedClaims = Buffer.from(JSON.stringify(params.tombstone), "utf8").toString(
      "base64url",
    );
    const signature = await params.signer.sign(Buffer.from(encodedClaims, "utf8"));
    const encodedSignature = Buffer.from(signature).toString("base64url");
    return ok(`${encodedClaims}.${encodedSignature}`);
  } catch (error) {
    return err({ code: "SIGNING_FAILED", reason: errorMessage(error) });
  }
}

/**
 * Verifies a tombstone entirely locally against a caller-supplied public key.
 * Fails closed — a malformed envelope or a bad signature is rejected, never
 * thrown — because an unauthenticated revocation push would otherwise let
 * anyone revoke any agent (a denial-of-service vector).
 */
export function verifyRevocationTombstone(params: {
  readonly tombstone: string;
  readonly publicKey: Uint8Array;
}): Result<RevocationTombstone, VerifyTombstoneError> {
  const { tombstone, publicKey } = params;
  const parts = tombstone.split(".");
  if (parts.length !== 2) {
    return err({ code: "MALFORMED_TOMBSTONE", reason: "expected exactly one '.' separator" });
  }
  const [encodedClaims, encodedSignature] = parts as [string, string];

  let claims: RevocationTombstone;
  try {
    const decoded: unknown = JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8"));
    if (!isRevocationTombstone(decoded)) {
      return err({ code: "MALFORMED_TOMBSTONE", reason: "claims missing required fields" });
    }
    claims = decoded;
  } catch (error) {
    return err({ code: "MALFORMED_TOMBSTONE", reason: errorMessage(error) });
  }

  const signature = Buffer.from(encodedSignature, "base64url");
  const signedData = Buffer.from(encodedClaims, "utf8");
  if (!verify(signature, signedData, publicKey)) {
    return err({ code: "SIGNATURE_INVALID" });
  }

  return ok(claims);
}

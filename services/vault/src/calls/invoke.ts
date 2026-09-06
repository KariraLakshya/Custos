import { verifyScopedToken, type SecretCipher } from "@custos/core";
import { err, type Result } from "@custos/contracts";
import type { Connector, ConnectorCallError } from "@custos/connectors";
import { loadToolCredential } from "../credentials/store.js";
import type { VaultDb } from "../db/client.js";

export type InvokeToolError =
  | { readonly code: "INVALID_TOKEN"; readonly reason: string }
  | { readonly code: "ACTION_MISMATCH" }
  | { readonly code: "UNKNOWN_TOOL"; readonly tool: string }
  | ConnectorCallError;

/**
 * Redeems a scoped token for one tool call. Token verification is entirely
 * local (CLAUDE.md section 3, hot path) — no DB or network access happens
 * until after the token has already checked out. The decrypted credential
 * lives only in this function's stack for the duration of the call and is
 * never logged (CLAUDE.md section 4).
 */
export async function invokeTool(params: {
  readonly db: VaultDb;
  readonly cipher: SecretCipher;
  readonly connectors: ReadonlyMap<string, Connector>;
  readonly token: string;
  readonly vaultPublicKey: Uint8Array;
  readonly action: string;
  readonly input: unknown;
  readonly now: Date;
}): Promise<Result<unknown, InvokeToolError>> {
  const { db, cipher, connectors, token, vaultPublicKey, action, input, now } = params;

  const verified = verifyScopedToken({ token, publicKey: vaultPublicKey, now });
  if (!verified.ok) {
    return err({ code: "INVALID_TOKEN", reason: verified.error.code });
  }
  const claims = verified.value;
  if (claims.action !== action) {
    return err({ code: "ACTION_MISMATCH" });
  }

  const connector = connectors.get(claims.tool);
  if (!connector) {
    return err({ code: "UNKNOWN_TOOL", tool: claims.tool });
  }

  const credential = await loadToolCredential({ db, cipher, tool: claims.tool });
  if (credential === null) {
    return err({ code: "UNKNOWN_TOOL", tool: claims.tool });
  }

  return connector.call({ action, input, credential });
}

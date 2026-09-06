import { eq } from "drizzle-orm";
import type { SecretCipher } from "@custos/core";
import { toolCredentials } from "../db/schema.js";
import type { VaultDb } from "../db/client.js";

/** Encrypts `secret` and upserts it as the stored credential for `tool`. */
export async function storeToolCredential(params: {
  readonly db: VaultDb;
  readonly cipher: SecretCipher;
  readonly tool: string;
  readonly secret: string;
}): Promise<void> {
  const { db, cipher, tool, secret } = params;
  const encrypted = await cipher.encrypt(new TextEncoder().encode(secret));
  const row = {
    tool,
    ciphertext: Buffer.from(encrypted.ciphertext).toString("base64"),
    nonce: Buffer.from(encrypted.nonce).toString("base64"),
  };
  await db
    .insert(toolCredentials)
    .values(row)
    .onConflictDoUpdate({
      target: toolCredentials.tool,
      set: { ciphertext: row.ciphertext, nonce: row.nonce },
    });
}

/** Loads and decrypts the stored credential for `tool`, or `null` if none is stored. */
export async function loadToolCredential(params: {
  readonly db: VaultDb;
  readonly cipher: SecretCipher;
  readonly tool: string;
}): Promise<string | null> {
  const { db, cipher, tool } = params;
  const [row] = await db
    .select()
    .from(toolCredentials)
    .where(eq(toolCredentials.tool, tool))
    .limit(1);
  if (!row) return null;

  const decrypted = await cipher.decrypt({
    ciphertext: new Uint8Array(Buffer.from(row.ciphertext, "base64")),
    nonce: new Uint8Array(Buffer.from(row.nonce, "base64")),
  });
  return new TextDecoder().decode(decrypted);
}

export async function toolCredentialExists(db: VaultDb, tool: string): Promise<boolean> {
  const [row] = await db
    .select({ tool: toolCredentials.tool })
    .from(toolCredentials)
    .where(eq(toolCredentials.tool, tool))
    .limit(1);
  return row !== undefined;
}

import { createLocalKeyProvider, type KeyProvider } from "@custos/core";
import { createKmsClient, createKmsKeyProvider, type KmsClient } from "@custos/kms";
import type { Env } from "../env.js";

const LOCAL_SIGNING_KEY_ID = "signing";

/**
 * The audit service's signing key, from configuration (ADR 0017 §3). It signs
 * the ledger's seals, which auditors verify long after they were made and
 * which are kept outside the database, so it must outlive the process: a dev
 * seed, or a KMS key whose private half never leaves AWS. Nothing is
 * contacted here; the server reads the public key at boot, so an unusable KMS
 * key fails the boot rather than the first seal.
 */
export function createSigningKey(
  env: Pick<Env, "AUDIT_SIGNING_SEED" | "AUDIT_SIGNING_KMS_KEY_ID"> &
    Partial<Pick<Env, "AUDIT_KEY_PROVIDER">>,
  deps: { readonly kmsClient?: KmsClient } = {},
): {
  readonly keyProvider: KeyProvider;
  readonly keyId: string;
} {
  if (env.AUDIT_KEY_PROVIDER === "kms") {
    return {
      keyProvider: createKmsKeyProvider(deps.kmsClient ?? createKmsClient()),
      keyId: env.AUDIT_SIGNING_KMS_KEY_ID as string,
    };
  }
  return {
    keyProvider: createLocalKeyProvider({
      importedKeys: {
        [LOCAL_SIGNING_KEY_ID]: Buffer.from(env.AUDIT_SIGNING_SEED as string, "hex"),
      },
    }),
    keyId: LOCAL_SIGNING_KEY_ID,
  };
}

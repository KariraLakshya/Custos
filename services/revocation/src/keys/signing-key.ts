import { createLocalKeyProvider, type KeyProvider } from "@custos/core";
import { createKmsClient, createKmsKeyProvider, type KmsClient } from "@custos/kms";
import type { Env } from "../env.js";

const LOCAL_SIGNING_KEY_ID = "signing";

/**
 * The revocation service's signing key, from configuration (ADR 0012, ADR
 * 0016). It signs every tombstone and the status list credential, and every
 * subscriber caches its public half, so it must outlive the process: a dev
 * seed, or a KMS key whose private half never leaves AWS. The env schema
 * guarantees the setting the chosen provider needs is present. Nothing is
 * contacted here; the server reads the public key at boot, so a missing or
 * unusable KMS key fails the boot rather than the first revocation.
 */
export function createSigningKey(
  env: Pick<Env, "REVOCATION_SIGNING_SEED" | "REVOCATION_SIGNING_KMS_KEY_ID"> &
    Partial<Pick<Env, "REVOCATION_KEY_PROVIDER">>,
  deps: { readonly kmsClient?: KmsClient } = {},
): {
  readonly keyProvider: KeyProvider;
  readonly keyId: string;
} {
  if (env.REVOCATION_KEY_PROVIDER === "kms") {
    return {
      keyProvider: createKmsKeyProvider(deps.kmsClient ?? createKmsClient()),
      keyId: env.REVOCATION_SIGNING_KMS_KEY_ID as string,
    };
  }
  return {
    keyProvider: createLocalKeyProvider({
      importedKeys: {
        [LOCAL_SIGNING_KEY_ID]: Buffer.from(env.REVOCATION_SIGNING_SEED as string, "hex"),
      },
    }),
    keyId: LOCAL_SIGNING_KEY_ID,
  };
}

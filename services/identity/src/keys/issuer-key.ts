import { KMSClient } from "@aws-sdk/client-kms";
import { createLocalKeyProvider, type KeyProvider } from "@custos/core";
import type { Env } from "../env.js";
import { createKmsKeyProvider } from "./kms-key-provider.js";

const LOCAL_ISSUER_KEY_ID = "issuer";

/**
 * The identity service's issuer key, from configuration (ADR 0007 decision 4).
 * Either way the key outlives the process: a dev seed, or a KMS key whose
 * private half never leaves AWS. The env schema guarantees the setting the
 * chosen provider needs is present. Nothing is contacted here; the server
 * reads the public key at boot, so a missing or unusable KMS key fails the
 * boot rather than the first registration.
 */
export function createIssuerKey(
  env: Env,
  deps: { readonly kmsClient?: Pick<KMSClient, "send"> } = {},
): { readonly keyProvider: KeyProvider; readonly keyId: string } {
  if (env.IDENTITY_KEY_PROVIDER === "kms") {
    return {
      keyProvider: createKmsKeyProvider(deps.kmsClient ?? new KMSClient({})),
      keyId: env.IDENTITY_ISSUER_KMS_KEY_ID as string,
    };
  }
  return {
    keyProvider: createLocalKeyProvider({
      importedKeys: {
        [LOCAL_ISSUER_KEY_ID]: Buffer.from(env.IDENTITY_ISSUER_SEED as string, "hex"),
      },
    }),
    keyId: LOCAL_ISSUER_KEY_ID,
  };
}

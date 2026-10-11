import { createLocalKeyProvider, type KeyProvider } from "@custos/core";
import type { Env } from "../env.js";

const LOCAL_SIGNING_KEY_ID = "signing";

/**
 * The revocation service's signing key, from configuration (ADR 0012). It
 * signs every tombstone and the status list credential, and every subscriber
 * caches its public half, so it must outlive the process: a key that changes
 * on restart forces each subscriber to re-resolve it and re-verify the whole
 * revocation list. Nothing is contacted here.
 */
export function createSigningKey(env: Pick<Env, "REVOCATION_SIGNING_SEED">): {
  readonly keyProvider: KeyProvider;
  readonly keyId: string;
} {
  return {
    keyProvider: createLocalKeyProvider({
      importedKeys: {
        [LOCAL_SIGNING_KEY_ID]: Buffer.from(env.REVOCATION_SIGNING_SEED, "hex"),
      },
    }),
    keyId: LOCAL_SIGNING_KEY_ID,
  };
}

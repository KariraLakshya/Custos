import { createLocalKeyProvider, type KeyProvider } from "@custos/core";
import type { PublisherConfig } from "./publish.js";

export const PUBLISHER_KEY_ID = "publisher";

export type ConfigError = { readonly code: "INVALID_CONFIG"; readonly reason: string };

export interface RawPublisherOptions {
  readonly domain?: string;
  readonly dir?: string;
  readonly out?: string;
  readonly validitySeconds?: string;
  readonly stampSeconds?: string;
  readonly maxClockSkewSeconds?: string;
}

function positiveInteger(value: string | undefined): number | undefined {
  if (value === undefined || !/^[1-9]\d{0,9}$/.test(value)) return undefined;
  return Number(value);
}

/**
 * Validates the publisher's settings before anything is read or written, so a
 * bad value refuses to start rather than failing at the first cycle. The
 * validity period and the stamp interval have no defaults (the TTL is explicit
 * configuration), and the stamp must be shorter than the validity period or
 * every list would expire between stamps.
 */
export function parsePublisherConfig(
  raw: RawPublisherOptions,
  options: { readonly needsStamp: boolean },
): { ok: true; value: PublisherConfig } | { ok: false; error: ConfigError } {
  const bad = (reason: string) => ({
    ok: false as const,
    error: { code: "INVALID_CONFIG" as const, reason },
  });
  if (!raw.domain)
    return bad("--domain is required (the domain the revocation DID is published under)");
  if (!raw.dir) return bad("--dir is required (where the journal and state are kept)");
  if (!raw.out) return bad("--out is required (the file a static server publishes)");

  const validitySeconds = positiveInteger(raw.validitySeconds);
  if (validitySeconds === undefined)
    return bad("--validity-seconds is required and must be a positive whole number");

  let stampSeconds = 1;
  if (options.needsStamp || raw.stampSeconds !== undefined) {
    const parsed = positiveInteger(raw.stampSeconds);
    if (parsed === undefined)
      return bad("--stamp-seconds is required and must be a positive whole number");
    if (parsed >= validitySeconds)
      return bad("--stamp-seconds must be shorter than --validity-seconds");
    stampSeconds = parsed;
  }

  const skew = raw.maxClockSkewSeconds === undefined ? 5 : Number(raw.maxClockSkewSeconds);
  if (!Number.isSafeInteger(skew) || skew < 0)
    return bad("--max-clock-skew-seconds must be a whole number, 0 or more");

  return {
    ok: true,
    value: {
      domain: raw.domain,
      dir: raw.dir,
      out: raw.out,
      validitySeconds,
      stampSeconds,
      maxClockSkewSeconds: skew,
    },
  };
}

/**
 * The publisher's signing key, from the environment only. A flag would land in
 * shell history; the seed is never printed, logged, or written to the state or
 * journal. A development stand-in: the key moves to KMS before this is used for
 * anything real (ADR 0014).
 */
export function publisherKeyFromEnv(
  env: Record<string, string | undefined>,
):
  | { ok: true; value: { keyProvider: KeyProvider; keyId: string } }
  | { ok: false; error: ConfigError } {
  const seed = env.CUSTOS_PUBLISHER_SIGNING_SEED;
  if (seed === undefined || !/^[0-9a-f]{64}$/i.test(seed)) {
    return {
      ok: false,
      error: {
        code: "INVALID_CONFIG",
        reason:
          "CUSTOS_PUBLISHER_SIGNING_SEED must be set to 64 hex characters (32 bytes), in the environment",
      },
    };
  }
  return {
    ok: true,
    value: {
      keyProvider: createLocalKeyProvider({
        importedKeys: { [PUBLISHER_KEY_ID]: Buffer.from(seed, "hex") },
      }),
      keyId: PUBLISHER_KEY_ID,
    },
  };
}

import { err, multibaseToPublicKey, ok, type Result, type TrustAnchor } from "@custos/core";
import { z } from "zod";

/**
 * A trust anchor plus where B fetches that organisation's signed status list.
 * The fetch URL is configuration only: it is never read from a credential.
 */
export type ConfiguredAnchor = TrustAnchor & { readonly statusFetchUrl: string };

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/**
 * https everywhere; plain http only for a loopback host, for local demos. The
 * host is read from the parsed URL, so `http://localhost.evil.com` is refused.
 * Embedded credentials are refused: they would end up in logs.
 */
function isAllowedFetchUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username !== "" || url.password !== "") return false;
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname);
}

const did = z
  .string()
  .min(1)
  .max(512)
  .refine((value) => value.startsWith("did:web:"), "must be a did:web identifier");

const anchorSchema = z
  .object({
    // Used in audit `policy.rule`, which is capped at 256 characters.
    domain: z.string().min(1).max(200),
    credentialIssuerDid: did,
    credentialIssuerPublicKey: z.string().min(1).max(128),
    statusIssuerDid: did,
    statusIssuerPublicKey: z.string().min(1).max(128),
    statusListId: z.string().min(1).max(2048),
    statusFetchUrl: z.string().min(1).max(2048).refine(isAllowedFetchUrl, "must be https"),
    // Required, no default: how stale a list may be is a security decision.
    maxStatusAgeSeconds: z.number().int().positive().max(31_536_000),
    enabled: z.boolean(),
  })
  .strict();

const MAX_ANCHORS = 64;

export interface AnchorConfigError {
  readonly code: "ANCHOR_CONFIG_INVALID";
  readonly issues: string[];
}

/**
 * Parses the configured trust anchors, or refuses the whole set. Duplicate
 * issuers or list ids are refused rather than resolved: `selectTrustAnchor`
 * takes the first match, so a duplicate could silently pin the wrong key.
 * Loading the configuration (file, environment) belongs to the embedder.
 */
export function parseTrustAnchors(input: unknown): Result<ConfiguredAnchor[], AnchorConfigError> {
  const parsed = z.array(anchorSchema).max(MAX_ANCHORS).safeParse(input);
  if (!parsed.success) {
    return err({
      code: "ANCHOR_CONFIG_INVALID",
      issues: parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`),
    });
  }

  const issues: string[] = [];
  const issuers = new Set<string>();
  const lists = new Set<string>();
  const anchors: ConfiguredAnchor[] = [];

  parsed.data.forEach((raw, index) => {
    if (issuers.has(raw.credentialIssuerDid)) {
      issues.push(`${index}.credentialIssuerDid: duplicate`);
    }
    if (lists.has(raw.statusListId)) issues.push(`${index}.statusListId: duplicate`);
    issuers.add(raw.credentialIssuerDid);
    lists.add(raw.statusListId);

    const credentialKey = multibaseToPublicKey(raw.credentialIssuerPublicKey);
    if (!credentialKey.ok) issues.push(`${index}.credentialIssuerPublicKey: not an Ed25519 key`);
    const statusKey = multibaseToPublicKey(raw.statusIssuerPublicKey);
    if (!statusKey.ok) issues.push(`${index}.statusIssuerPublicKey: not an Ed25519 key`);
    if (!credentialKey.ok || !statusKey.ok) return;

    anchors.push({
      domain: raw.domain,
      credentialIssuerDid: raw.credentialIssuerDid,
      credentialIssuerPublicKey: credentialKey.value,
      statusIssuerDid: raw.statusIssuerDid,
      statusIssuerPublicKey: statusKey.value,
      statusListId: raw.statusListId,
      statusFetchUrl: raw.statusFetchUrl,
      maxStatusAgeSeconds: raw.maxStatusAgeSeconds,
      enabled: raw.enabled,
    });
  });

  return issues.length > 0 ? err({ code: "ANCHOR_CONFIG_INVALID", issues }) : ok(anchors);
}

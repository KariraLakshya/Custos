import { randomBytes as nodeRandomBytes, timingSafeEqual } from "node:crypto";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { PrincipalKind } from "./scopes.js";

/**
 * `custos_<kind>_<id>_<secret>` (ADR 0008 §4). The fixed prefix lets secret
 * scanners recognise a leaked key; `<id>` (16 hex) finds the stored record
 * without a scan; `<secret>` is 32 random bytes as unpadded base64url (43
 * characters, which may itself contain `_` — hence the anchored pattern
 * rather than a split). The pattern also bounds the input length.
 */
const API_KEY_PATTERN = /^custos_(operator|service)_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;

export interface ParsedApiKey {
  readonly kind: PrincipalKind;
  readonly id: string;
  readonly secret: string;
}

export function parseApiKey(token: string): ParsedApiKey | null {
  const match = API_KEY_PATTERN.exec(token);
  if (!match) return null;
  return { kind: match[1] as PrincipalKind, id: match[2]!, secret: match[3]! };
}

/** SHA-256, hex. A slow hash adds nothing for 256 random bits (ADR 0008 §4). */
export function hashApiKeySecret(secret: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(secret)));
}

/** Constant-time comparison of a presented secret against a stored hash. */
export function secretMatchesHash(secret: string, storedHash: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(storedHash)) return false;
  return timingSafeEqual(hexToBytes(hashApiKeySecret(secret)), hexToBytes(storedHash));
}

export interface GeneratedApiKey {
  readonly id: string;
  /** The full key. Shown once to its holder; never stored or logged. */
  readonly token: string;
  readonly secretHash: string;
}

export function generateApiKey(
  kind: PrincipalKind,
  randomBytes: (length: number) => Uint8Array = nodeRandomBytes,
): GeneratedApiKey {
  const id = bytesToHex(randomBytes(8));
  const secret = Buffer.from(randomBytes(32)).toString("base64url");
  return { id, token: `custos_${kind}_${id}_${secret}`, secretHash: hashApiKeySecret(secret) };
}

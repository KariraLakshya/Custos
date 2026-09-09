import { gunzipSync, gzipSync } from "node:zlib";
import { err, ok, type Result } from "../result.js";

/**
 * W3C Bitstring Status List v1.0 (the Recommendation that superseded the
 * StatusList2021 draft — see docs/adr/0005-revocation-architecture.md).
 *
 * The spec mandates a minimum bitstring of 16KB — 131,072 entries — so the
 * size of the published list leaks nothing about how many credentials an
 * issuer has actually revoked (herd privacy). A verifier downloads the whole
 * list and reads one bit, so the issuer never learns which entry it wanted.
 */
export const MINIMUM_STATUS_LIST_ENTRIES = 131_072;

/**
 * Multibase prefix `u` = base64url, no padding. Bitstring Status List types
 * `encodedList` as multibase, unlike StatusList2021's bare base64url.
 */
const MULTIBASE_BASE64URL_PREFIX = "u";

export const BITSTRING_STATUS_LIST_ENTRY_TYPE = "BitstringStatusListEntry";
export const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE = "BitstringStatusListCredential";
export const BITSTRING_STATUS_LIST_TYPE = "BitstringStatusList";

export type StatusPurpose = "revocation" | "suspension";

export type StatusListError =
  | { readonly code: "INDEX_OUT_OF_RANGE"; readonly index: number; readonly entries: number }
  | { readonly code: "MALFORMED_STATUS_LIST"; readonly reason: string };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Bit `index` lives in byte `index >> 3` at position `7 - (index & 7)` —
 * most-significant-bit-first within each byte, which is what the spec's
 * reference implementations interoperate on. Get this backwards and a list
 * we publish reads as a different set of revocations to everyone else.
 */
function locate(index: number): { readonly byte: number; readonly mask: number } {
  return { byte: index >> 3, mask: 0b1000_0000 >> (index & 7) };
}

function entryCount(list: Uint8Array): number {
  return list.length * 8;
}

function outOfRange(list: Uint8Array, index: number): boolean {
  return !Number.isInteger(index) || index < 0 || index >= entryCount(list);
}

export function createStatusList(entries: number = MINIMUM_STATUS_LIST_ENTRIES): Uint8Array {
  const size = Math.ceil(Math.max(entries, MINIMUM_STATUS_LIST_ENTRIES) / 8);
  return new Uint8Array(size);
}

/**
 * Returns a new list with `index` set — never mutates the input, so a caller
 * holding the previous list keeps a stable value. `index` is attacker-
 * influenced (it arrives inside a credential), so it is range-checked rather
 * than trusted.
 */
export function setRevoked(
  list: Uint8Array,
  index: number,
  revoked: boolean,
): Result<Uint8Array, StatusListError> {
  if (outOfRange(list, index)) {
    return err({ code: "INDEX_OUT_OF_RANGE", index, entries: entryCount(list) });
  }
  const { byte, mask } = locate(index);
  const next = Uint8Array.from(list);
  // `byte` is in range (checked above); the assertions only satisfy
  // noUncheckedIndexedAccess.
  next[byte] = revoked ? next[byte]! | mask : next[byte]! & ~mask;
  return ok(next);
}

export function isRevoked(list: Uint8Array, index: number): Result<boolean, StatusListError> {
  if (outOfRange(list, index)) {
    return err({ code: "INDEX_OUT_OF_RANGE", index, entries: entryCount(list) });
  }
  const { byte, mask } = locate(index);
  return ok((list[byte]! & mask) !== 0);
}

/**
 * GZIP, then multibase base64url, per the spec's `encodedList`. Round-trip
 * stability is what matters here, not byte-identical output: gzip headers
 * are not guaranteed stable across zlib versions.
 */
export function encodeStatusList(list: Uint8Array): string {
  return `${MULTIBASE_BASE64URL_PREFIX}${gzipSync(list).toString("base64url")}`;
}

/**
 * Fails closed on anything that is not a valid multibase-gzipped bitstring:
 * this input is fetched from a remote status list endpoint, so malformed,
 * truncated, or hostile payloads are expected rather than exceptional.
 */
export function decodeStatusList(encoded: string): Result<Uint8Array, StatusListError> {
  if (!encoded.startsWith(MULTIBASE_BASE64URL_PREFIX)) {
    return err({
      code: "MALFORMED_STATUS_LIST",
      reason: `expected multibase base64url ("${MULTIBASE_BASE64URL_PREFIX}") prefix`,
    });
  }
  try {
    const compressed = Buffer.from(encoded.slice(MULTIBASE_BASE64URL_PREFIX.length), "base64url");
    if (compressed.length === 0) {
      return err({ code: "MALFORMED_STATUS_LIST", reason: "empty encoded list" });
    }
    const list = new Uint8Array(gunzipSync(compressed));
    if (list.length === 0) {
      return err({ code: "MALFORMED_STATUS_LIST", reason: "decoded list is empty" });
    }
    return ok(list);
  } catch (error) {
    return err({ code: "MALFORMED_STATUS_LIST", reason: errorMessage(error) });
  }
}

/**
 * The `credentialStatus` block embedded in each issued agent credential,
 * pointing at this agent's one bit in the published list. `statusListIndex`
 * is a string per the spec, not a number.
 */
export interface BitstringStatusListEntry {
  readonly id: string;
  readonly type: typeof BITSTRING_STATUS_LIST_ENTRY_TYPE;
  readonly statusPurpose: StatusPurpose;
  readonly statusListIndex: string;
  readonly statusListCredential: string;
}

export function buildStatusListEntry(params: {
  readonly statusListCredential: string;
  readonly statusListIndex: number;
  readonly statusPurpose?: StatusPurpose;
}): BitstringStatusListEntry {
  const { statusListCredential, statusListIndex, statusPurpose = "revocation" } = params;
  return {
    id: `${statusListCredential}#${statusListIndex}`,
    type: BITSTRING_STATUS_LIST_ENTRY_TYPE,
    statusPurpose,
    statusListIndex: String(statusListIndex),
    statusListCredential,
  };
}

/**
 * The `credentialSubject` of the published status list credential. `ttl` is
 * the spec's own bounded-staleness knob (milliseconds a verifier may cache
 * this list) — CLAUDE.md section 3 requires that bound be explicit config,
 * never an accident.
 */
export interface BitstringStatusListSubject {
  readonly id: string;
  readonly type: typeof BITSTRING_STATUS_LIST_TYPE;
  readonly statusPurpose: StatusPurpose;
  readonly encodedList: string;
  readonly ttl?: number;
}

export function buildStatusListSubject(params: {
  readonly id: string;
  readonly list: Uint8Array;
  readonly statusPurpose?: StatusPurpose;
  readonly ttlMs?: number;
}): BitstringStatusListSubject {
  const { id, list, statusPurpose = "revocation", ttlMs } = params;
  return {
    id,
    type: BITSTRING_STATUS_LIST_TYPE,
    statusPurpose,
    encodedList: encodeStatusList(list),
    ...(ttlMs === undefined ? {} : { ttl: ttlMs }),
  };
}

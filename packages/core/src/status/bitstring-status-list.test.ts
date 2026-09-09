import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  MINIMUM_STATUS_LIST_ENTRIES,
  buildStatusListEntry,
  buildStatusListSubject,
  createStatusList,
  decodeStatusList,
  encodeStatusList,
  isRevoked,
  setRevoked,
} from "./bitstring-status-list.js";

function unwrap<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  if (!result.ok) throw new Error(`expected ok, got ${JSON.stringify(result.error)}`);
  return result.value;
}

describe("createStatusList", () => {
  it("defaults to the spec minimum of 131,072 entries (16KB)", () => {
    const list = createStatusList();
    expect(list).toHaveLength(MINIMUM_STATUS_LIST_ENTRIES / 8);
    expect(list).toHaveLength(16_384);
  });

  it("never returns a list smaller than the spec minimum, even if asked", () => {
    // A short list would leak how few credentials the issuer has issued.
    expect(createStatusList(8)).toHaveLength(MINIMUM_STATUS_LIST_ENTRIES / 8);
  });

  it("honours a request larger than the minimum", () => {
    expect(createStatusList(MINIMUM_STATUS_LIST_ENTRIES * 2)).toHaveLength(
      (MINIMUM_STATUS_LIST_ENTRIES * 2) / 8,
    );
  });

  it("starts with every entry unrevoked", () => {
    const list = createStatusList();
    expect(unwrap(isRevoked(list, 0))).toBe(false);
    expect(unwrap(isRevoked(list, 131_071))).toBe(false);
    expect(list.every((byte) => byte === 0)).toBe(true);
  });
});

describe("setRevoked / isRevoked", () => {
  it("round-trips a revoked entry", () => {
    const list = unwrap(setRevoked(createStatusList(), 42, true));
    expect(unwrap(isRevoked(list, 42))).toBe(true);
  });

  it("leaves neighbouring entries untouched", () => {
    const list = unwrap(setRevoked(createStatusList(), 42, true));
    expect(unwrap(isRevoked(list, 41))).toBe(false);
    expect(unwrap(isRevoked(list, 43))).toBe(false);
  });

  it("clears an entry when set back to false", () => {
    const revoked = unwrap(setRevoked(createStatusList(), 42, true));
    const cleared = unwrap(setRevoked(revoked, 42, false));
    expect(unwrap(isRevoked(cleared, 42))).toBe(false);
  });

  it("does not mutate the input list", () => {
    const original = createStatusList();
    setRevoked(original, 42, true);
    expect(unwrap(isRevoked(original, 42))).toBe(false);
  });

  it("records several revocations independently", () => {
    let list = createStatusList();
    for (const index of [0, 7, 8, 9, 1000, 131_071]) {
      list = unwrap(setRevoked(list, index, true));
    }
    for (const index of [0, 7, 8, 9, 1000, 131_071]) {
      expect(unwrap(isRevoked(list, index))).toBe(true);
    }
    expect(unwrap(isRevoked(list, 1))).toBe(false);
  });

  // Bit order is an interop contract: get it wrong and a list we publish
  // reads as a different set of revocations to every other implementation.
  it("packs bit 0 as the most significant bit of byte 0", () => {
    const list = unwrap(setRevoked(createStatusList(), 0, true));
    expect(list[0]).toBe(0b1000_0000);
  });

  it("packs bit 7 as the least significant bit of byte 0", () => {
    const list = unwrap(setRevoked(createStatusList(), 7, true));
    expect(list[0]).toBe(0b0000_0001);
  });

  it("packs bit 8 as the most significant bit of byte 1", () => {
    const list = unwrap(setRevoked(createStatusList(), 8, true));
    expect(list[0]).toBe(0);
    expect(list[1]).toBe(0b1000_0000);
  });
});

describe("status list index validation", () => {
  const list = createStatusList();

  it.each([
    ["negative", -1],
    ["past the end", MINIMUM_STATUS_LIST_ENTRIES],
    ["far past the end", 10_000_000],
    ["fractional", 1.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
  ])("rejects a %s index on isRevoked", (_label, index) => {
    const result = isRevoked(list, index);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("INDEX_OUT_OF_RANGE");
  });

  it.each([
    ["negative", -1],
    ["past the end", MINIMUM_STATUS_LIST_ENTRIES],
    ["fractional", 1.5],
  ])("rejects a %s index on setRevoked", (_label, index) => {
    const result = setRevoked(list, index, true);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("INDEX_OUT_OF_RANGE");
  });

  it("reports the list size alongside an out-of-range index", () => {
    const result = isRevoked(list, 999_999);
    expect(result.ok).toBe(false);
    if (!result.ok && result.error.code === "INDEX_OUT_OF_RANGE") {
      expect(result.error.entries).toBe(MINIMUM_STATUS_LIST_ENTRIES);
      expect(result.error.index).toBe(999_999);
    }
  });
});

describe("encodeStatusList / decodeStatusList", () => {
  it("encodes with the multibase base64url prefix", () => {
    expect(encodeStatusList(createStatusList()).startsWith("u")).toBe(true);
  });

  it("compresses an empty list far below its raw 16KB size", () => {
    // Herd privacy costs nothing on the wire: 16KB of zeroes gzips tiny.
    expect(encodeStatusList(createStatusList()).length).toBeLessThan(200);
  });

  it("round-trips a list with revocations intact", () => {
    let list = createStatusList();
    for (const index of [0, 42, 8_191, 131_071]) {
      list = unwrap(setRevoked(list, index, true));
    }
    const decoded = unwrap(decodeStatusList(encodeStatusList(list)));
    expect(decoded).toEqual(list);
    for (const index of [0, 42, 8_191, 131_071]) {
      expect(unwrap(isRevoked(decoded, index))).toBe(true);
    }
    expect(unwrap(isRevoked(decoded, 43))).toBe(false);
  });

  it("rejects an encoded list without the multibase prefix", () => {
    const withoutPrefix = encodeStatusList(createStatusList()).slice(1);
    const result = decodeStatusList(withoutPrefix);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("MALFORMED_STATUS_LIST");
  });

  it.each([
    ["empty string", ""],
    ["prefix only", "u"],
    ["not base64url-decodable gzip", "unot-actually-gzipped-data"],
    [
      "truncated gzip stream",
      `u${gzipSync(createStatusList()).toString("base64url").slice(0, 12)}`,
    ],
  ])("fails closed on %s rather than throwing", (_label, encoded) => {
    const result = decodeStatusList(encoded);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("MALFORMED_STATUS_LIST");
  });

  it("rejects a validly gzipped but empty payload", () => {
    const result = decodeStatusList(`u${gzipSync(new Uint8Array(0)).toString("base64url")}`);
    expect(result.ok).toBe(false);
    if (!result.ok && result.error.code === "MALFORMED_STATUS_LIST") {
      expect(result.error.reason).toContain("empty");
    }
  });
});

describe("buildStatusListEntry", () => {
  it("builds the credentialStatus block a credential embeds", () => {
    const entry = buildStatusListEntry({
      statusListCredential: "https://custos.example/status/1",
      statusListIndex: 42,
    });
    expect(entry).toEqual({
      id: "https://custos.example/status/1#42",
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "42",
      statusListCredential: "https://custos.example/status/1",
    });
  });

  it("encodes statusListIndex as a string, per the spec", () => {
    const entry = buildStatusListEntry({
      statusListCredential: "https://custos.example/status/1",
      statusListIndex: 0,
    });
    expect(entry.statusListIndex).toBe("0");
    expect(typeof entry.statusListIndex).toBe("string");
  });

  it("supports a suspension purpose", () => {
    const entry = buildStatusListEntry({
      statusListCredential: "https://custos.example/status/1",
      statusListIndex: 7,
      statusPurpose: "suspension",
    });
    expect(entry.statusPurpose).toBe("suspension");
  });
});

describe("buildStatusListSubject", () => {
  it("builds a decodable status list credential subject", () => {
    const list = unwrap(setRevoked(createStatusList(), 42, true));
    const subject = buildStatusListSubject({ id: "https://custos.example/status/1", list });
    expect(subject.type).toBe("BitstringStatusList");
    expect(subject.statusPurpose).toBe("revocation");
    const decoded = unwrap(decodeStatusList(subject.encodedList));
    expect(unwrap(isRevoked(decoded, 42))).toBe(true);
  });

  it("omits ttl when no bound is configured", () => {
    const subject = buildStatusListSubject({
      id: "https://custos.example/status/1",
      list: createStatusList(),
    });
    expect(subject.ttl).toBeUndefined();
    expect("ttl" in subject).toBe(false);
  });

  it("publishes an explicit staleness bound when configured", () => {
    const subject = buildStatusListSubject({
      id: "https://custos.example/status/1",
      list: createStatusList(),
      ttlMs: 5_000,
    });
    expect(subject.ttl).toBe(5_000);
  });

  it("exposes the credential type constant callers wrap the subject in", () => {
    expect(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE).toBe("BitstringStatusListCredential");
  });
});

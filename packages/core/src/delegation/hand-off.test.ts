import { describe, expect, it } from "vitest";
import { generateKeyPair, verify } from "../crypto/ed25519.js";
import {
  buildHandOff,
  HAND_OFF_TYPE,
  handOffHash,
  isDelegatedGrantList,
  MAX_ACTIONS_PER_GRANT,
  MAX_GRANTS_PER_HAND_OFF,
} from "./hand-off.js";

const NOW = new Date("2026-11-02T10:00:00.000Z");
const keys = generateKeyPair();
const base = {
  from: "did:web:id.example:agents:a",
  to: "did:web:id.example:agents:b",
  grants: [{ tool: "mock-database", actions: ["query"] }],
  depth: 0,
  now: NOW,
  ttlSeconds: 600,
  secretKey: keys.secretKey,
};

function decode(handOff: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(handOff.split(".")[0]!, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
}

describe("buildHandOff", () => {
  it("signs the claims with the delegator's key", () => {
    const handOff = buildHandOff({ ...base, jti: "j-1" });
    const [claims, signature] = handOff.split(".") as [string, string];
    expect(
      verify(Buffer.from(signature, "base64url"), Buffer.from(claims, "utf8"), keys.publicKey),
    ).toBe(true);
    expect(decode(handOff)).toEqual({
      typ: HAND_OFF_TYPE,
      iss: base.from,
      sub: base.to,
      grants: base.grants,
      depth: 0,
      prev: null,
      iat: NOW.getTime() / 1000,
      exp: NOW.getTime() / 1000 + 600,
      jti: "j-1",
    });
  });

  it("links to the hand-off it extends by its hash, and makes a fresh jti by default", () => {
    const first = buildHandOff({ ...base, depth: 1 });
    const second = buildHandOff({ ...base, previous: first });
    expect(decode(second).prev).toBe(handOffHash(first));
    expect(decode(first).jti).not.toBe(decode(second).jti);
  });

  it("refuses grants that are empty, too many, or have bad tools or actions", () => {
    const bad = [
      [],
      Array.from({ length: MAX_GRANTS_PER_HAND_OFF + 1 }, (_, i) => ({
        tool: `t${i}`,
        actions: ["a"],
      })),
      [{ tool: "", actions: ["a"] }],
      [{ tool: "t".repeat(129), actions: ["a"] }],
      [{ tool: "t", actions: [] }],
      [{ tool: "t", actions: [""] }],
      [{ tool: "t", actions: Array.from({ length: MAX_ACTIONS_PER_GRANT + 1 }, () => "a") }],
    ];
    for (const grants of bad) {
      expect(() => buildHandOff({ ...base, grants })).toThrow(/grants/);
    }
  });

  it("refuses a negative or fractional depth and a non-positive ttl", () => {
    expect(() => buildHandOff({ ...base, depth: -1 })).toThrow(/depth/);
    expect(() => buildHandOff({ ...base, depth: 0.5 })).toThrow(/depth/);
    expect(() => buildHandOff({ ...base, ttlSeconds: 0 })).toThrow(/ttlSeconds/);
    expect(() => buildHandOff({ ...base, ttlSeconds: 1.5 })).toThrow(/ttlSeconds/);
  });
});

describe("isDelegatedGrantList", () => {
  it("refuses non-arrays and grants that are not objects or lack an action list", () => {
    expect(isDelegatedGrantList("mock-database")).toBe(false);
    expect(isDelegatedGrantList([null])).toBe(false);
    expect(isDelegatedGrantList(["mock-database"])).toBe(false);
    expect(isDelegatedGrantList([{ tool: "t", actions: "a" }])).toBe(false);
    expect(isDelegatedGrantList([{ tool: "t", actions: ["a", "b"] }])).toBe(true);
  });
});

describe("handOffHash", () => {
  it("is the base64url SHA-256 of the exact string", () => {
    expect(handOffHash("a.b")).toBe(handOffHash("a.b"));
    expect(handOffHash("a.b")).not.toBe(handOffHash("a.c"));
    expect(handOffHash("")).toBe("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
  });
});

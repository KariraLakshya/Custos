import { describe, expect, it } from "vitest";
import { DID_MAX_LENGTH, didSchema, PAGE_LIMIT_MAX, pageLimitSchema } from "./reads.js";

describe("didSchema", () => {
  it.each([
    "did:web:localhost%3A4001:agents:3f2b8c1e-1111-4111-8111-111111111111",
    "did:web:example.com",
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    `did:web:${"a".repeat(DID_MAX_LENGTH - "did:web:".length)}`,
  ])("accepts %s", (did) => {
    expect(didSchema.safeParse(did).success).toBe(true);
  });

  it.each([
    ["empty", ""],
    ["not a DID", "3f2b8c1e-1111-4111-8111-111111111111"],
    ["no method-specific id", "did:web:"],
    ["an upper-case method", "did:WEB:example.com"],
    ["a space", "did:web:exa mple.com"],
    ["a newline", "did:web:example.com\n"],
    ["a slash", "did:web:example.com/agents"],
    ["too long", `did:web:${"a".repeat(DID_MAX_LENGTH)}`],
  ])("refuses %s", (_label, did) => {
    expect(didSchema.safeParse(did).success).toBe(false);
  });

  it.each([42, null, ["did:web:a"]])("refuses the non-string %j", (value) => {
    expect(didSchema.safeParse(value).success).toBe(false);
  });
});

describe("pageLimitSchema", () => {
  it.each([
    ["1", 1],
    ["50", 50],
    [String(PAGE_LIMIT_MAX), PAGE_LIMIT_MAX],
  ])("accepts %s", (value, limit) => {
    expect(pageLimitSchema.safeParse(value)).toEqual({ success: true, data: limit });
  });

  it.each(["0", "-1", "01", "1.5", "1e2", " 5", "", "abc", String(PAGE_LIMIT_MAX + 1), "99999"])(
    "refuses %j",
    (value) => {
      expect(pageLimitSchema.safeParse(value).success).toBe(false);
    },
  );
});

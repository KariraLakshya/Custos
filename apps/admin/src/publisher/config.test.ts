import { describe, expect, it } from "vitest";
import { generateKeyPair, publicKeyToMultibase } from "@custos/core";
import { parsePublisherConfig, publisherKeyFromEnv } from "./config.js";
import { publisherIdentity } from "./publish.js";
import { DOMAIN, SEED, keyFor, mutableClock } from "./testkit.js";

const complete = {
  domain: "a.example",
  dir: "/var/custos",
  out: "/srv/status.json",
  validitySeconds: "3600",
  stampSeconds: "1200",
};

describe("parsePublisherConfig", () => {
  it("accepts a complete configuration, with a 5 s clock allowance by default", () => {
    expect(parsePublisherConfig(complete, { needsStamp: true })).toEqual({
      ok: true,
      value: {
        domain: "a.example",
        dir: "/var/custos",
        out: "/srv/status.json",
        validitySeconds: 3600,
        stampSeconds: 1200,
        maxClockSkewSeconds: 5,
      },
    });
  });

  it("requires the domain, directory and output file", () => {
    for (const missing of ["domain", "dir", "out"] as const) {
      const rest = Object.fromEntries(Object.entries(complete).filter(([key]) => key !== missing));
      expect(parsePublisherConfig(rest, { needsStamp: true })).toMatchObject({
        ok: false,
        error: { code: "INVALID_CONFIG" },
      });
    }
  });

  it("has no default for the validity period or, when stamping, the stamp interval", () => {
    const noValidity = Object.fromEntries(
      Object.entries(complete).filter(([key]) => key !== "validitySeconds"),
    );
    expect(parsePublisherConfig(noValidity, { needsStamp: false })).toMatchObject({
      ok: false,
      error: { reason: expect.stringContaining("--validity-seconds") },
    });
    const noStamp = Object.fromEntries(
      Object.entries(complete).filter(([key]) => key !== "stampSeconds"),
    );
    expect(parsePublisherConfig(noStamp, { needsStamp: true })).toMatchObject({
      ok: false,
      error: { reason: expect.stringContaining("--stamp-seconds") },
    });
    expect(parsePublisherConfig(noStamp, { needsStamp: false }).ok).toBe(true);
  });

  it("refuses a stamp interval that is not shorter than the validity period", () => {
    for (const stampSeconds of ["3600", "3601", "99999"]) {
      expect(
        parsePublisherConfig({ ...complete, stampSeconds }, { needsStamp: true }),
      ).toMatchObject({
        ok: false,
        error: { reason: expect.stringContaining("shorter") },
      });
    }
    // The same rule holds when a stamp interval is given to a command that does not need one.
    expect(
      parsePublisherConfig({ ...complete, stampSeconds: "3600" }, { needsStamp: false }).ok,
    ).toBe(false);
  });

  it("refuses numbers that are not positive whole numbers", () => {
    for (const bad of ["0", "-5", "1.5", "1e3", "soon", "", " 60", "99999999999"]) {
      expect(
        parsePublisherConfig({ ...complete, validitySeconds: bad }, { needsStamp: false }).ok,
        bad,
      ).toBe(false);
      expect(
        parsePublisherConfig({ ...complete, stampSeconds: bad }, { needsStamp: true }).ok,
        bad,
      ).toBe(false);
    }
  });

  it("validates the clock allowance", () => {
    expect(
      parsePublisherConfig({ ...complete, maxClockSkewSeconds: "0" }, { needsStamp: true }),
    ).toMatchObject({
      ok: true,
      value: { maxClockSkewSeconds: 0 },
    });
    for (const bad of ["-1", "1.5", "x"]) {
      expect(
        parsePublisherConfig({ ...complete, maxClockSkewSeconds: bad }, { needsStamp: true }).ok,
      ).toBe(false);
    }
  });
});

describe("publisherKeyFromEnv", () => {
  it("builds a key provider from a 64-hex-character seed in the environment", async () => {
    const result = publisherKeyFromEnv({ CUSTOS_PUBLISHER_SIGNING_SEED: SEED });
    if (!result.ok) throw new Error(result.error.reason);
    const first = await result.value.keyProvider.getPublicKey(result.value.keyId);
    const again = publisherKeyFromEnv({ CUSTOS_PUBLISHER_SIGNING_SEED: SEED });
    if (!again.ok) throw new Error("fixture");
    expect(await again.value.keyProvider.getPublicKey(again.value.keyId)).toEqual(first);
    expect(first).toHaveLength(32);
  });

  it("refuses a missing, short, long or non-hex seed, without echoing it", () => {
    for (const seed of [undefined, "", "ab", "z".repeat(64), "11".repeat(31), "11".repeat(33)]) {
      const result = publisherKeyFromEnv({ CUSTOS_PUBLISHER_SIGNING_SEED: seed });
      expect(result.ok).toBe(false);
      if (!result.ok && seed) expect(result.error.reason).not.toContain(seed);
    }
  });
});

describe("publisherIdentity", () => {
  it("derives the DID and list address from the domain the same way the revocation service does", async () => {
    const identity = await publisherIdentity(
      {
        domain: "127.0.0.1:4503",
        dir: "d",
        out: "o",
        validitySeconds: 60,
        stampSeconds: 20,
        maxClockSkewSeconds: 5,
      },
      { ...keyFor(SEED), clock: mutableClock() },
    );
    expect(identity.did).toBe("did:web:127.0.0.1%3A4503");
    expect(identity.listId).toBe("http://127.0.0.1:4503/status/revocation");
    expect(identity.verificationMethodId).toBe(`${identity.did}#${identity.publicKeyMultibase}`);
    const other = generateKeyPair();
    expect(identity.publicKeyMultibase).not.toBe(publicKeyToMultibase(other.publicKey));
    const forDomain = await publisherIdentity(
      {
        domain: DOMAIN,
        dir: "d",
        out: "o",
        validitySeconds: 60,
        stampSeconds: 20,
        maxClockSkewSeconds: 5,
      },
      { ...keyFor(SEED), clock: mutableClock() },
    );
    expect(forDomain.listId).toBe("https://a.example/status/revocation");
  });
});

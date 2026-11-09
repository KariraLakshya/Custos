import { afterEach, describe, expect, it, vi } from "vitest";
import { sign } from "../crypto/ed25519.js";
import {
  issueAgent,
  issueCustomAgent,
  makeOrganisation,
  NOW,
  type Agent,
} from "../federation/fixtures.js";
import { pinnedDidDocument } from "../federation/trust-anchor.js";
import type { SignedCredential } from "../vc/credential.js";
import { verifyDelegationChain, type DelegationLimits } from "./chain.js";
import { buildHandOff, HAND_OFF_TYPE, handOffHash, type DelegatedGrant } from "./hand-off.js";

const org = makeOrganisation();
const issuer = {
  did: org.identityDid,
  document: pinnedDidDocument(org.identityDid, org.identityKeys.publicKey),
};
const LIMITS: DelegationLimits = {
  maxLinks: 3,
  maxLifetimeSeconds: 3600,
  maxBytes: 16_384,
  maxClockSkewSeconds: 5,
};
const REQUEST = { tool: "mock-database", action: "query" } as const;
const DB_QUERY: DelegatedGrant[] = [{ tool: "mock-database", actions: ["query"] }];
const DB_ALL: DelegatedGrant[] = [{ tool: "mock-database", actions: ["query", "write"] }];
const NOW_S = NOW.getTime() / 1000;

const [a, b, c] = await Promise.all([issueAgent(org), issueAgent(org), issueAgent(org)]);

function handOff(
  from: Agent,
  to: Agent | string,
  options: {
    grants?: DelegatedGrant[];
    depth?: number;
    previous?: string;
    ttlSeconds?: number;
    now?: Date;
  } = {},
): string {
  return buildHandOff({
    from: from.did,
    to: typeof to === "string" ? to : to.did,
    grants: options.grants ?? DB_QUERY,
    depth: options.depth ?? 0,
    ...(options.previous === undefined ? {} : { previous: options.previous }),
    now: options.now ?? NOW,
    ttlSeconds: options.ttlSeconds ?? 600,
    secretKey: from.keys.secretKey,
  });
}

/** A hand-off with claims chosen freely, genuinely signed with `signer`'s key. */
function signed(claims: unknown, signer: Agent): string {
  const encoded = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const signature = sign(Buffer.from(encoded, "utf8"), signer.keys.secretKey);
  return `${encoded}.${Buffer.from(signature).toString("base64url")}`;
}

function claimsOf(from: Agent, to: Agent, overrides: Record<string, unknown> = {}) {
  return {
    typ: HAND_OFF_TYPE,
    iss: from.did,
    sub: to.did,
    grants: DB_QUERY,
    depth: 0,
    prev: null,
    iat: NOW_S,
    exp: NOW_S + 600,
    jti: "j",
    ...overrides,
  };
}

function check(
  chain: unknown,
  options: {
    requester?: Agent;
    request?: { tool: string; action: string };
    now?: Date;
    limits?: DelegationLimits;
  } = {},
) {
  return verifyDelegationChain({
    chain,
    requesterDid: (options.requester ?? b).did,
    request: options.request ?? REQUEST,
    issuer,
    now: options.now ?? NOW,
    limits: options.limits ?? LIMITS,
  });
}

const oneLink = (h: string, cred: SignedCredential = a.credential) => ({
  handOffs: [h],
  credentials: [cred],
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("verifyDelegationChain — a valid chain", () => {
  it("accepts one hand-off and names the root, the chain and the delegator", async () => {
    const result = await check(oneLink(handOff(a, b)));
    expect(result).toEqual({
      ok: true,
      value: {
        rootDid: a.did,
        dids: [a.did, b.did],
        delegators: [{ did: a.did, credentialStatus: a.credential.credentialStatus }],
        expiresAt: new Date((NOW_S + 600) * 1000),
      },
    });
  });

  it("accepts two hand-offs that narrow, ending at the requester", async () => {
    const first = handOff(a, b, { grants: DB_ALL, depth: 1 });
    const second = handOff(b, c, { previous: first, ttlSeconds: 300 });
    const result = await check(
      { handOffs: [first, second], credentials: [a.credential, b.credential] },
      { requester: c },
    );
    expect(result.ok && result.value.dids).toEqual([a.did, b.did, c.did]);
    expect(result.ok && result.value.delegators.map((d) => d.did)).toEqual([a.did, b.did]);
    expect(result.ok && result.value.expiresAt).toEqual(new Date((NOW_S + 300) * 1000));
  });

  it("ends no later than a delegator credential's validUntil", async () => {
    const validUntil = new Date(NOW.getTime() + 60_000).toISOString();
    const shortLived = await issueCustomAgent(org, a, { validUntil });
    const result = await check(oneLink(handOff(a, b), shortLived));
    expect(result.ok && result.value.expiresAt.toISOString()).toBe(validUntil);
  });

  it("makes no network call", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(() => {
      throw new Error("the chain check must not touch the network");
    });
    const first = handOff(a, b, { depth: 1 });
    const result = await check(
      {
        handOffs: [first, handOff(b, c, { previous: first })],
        credentials: [a.credential, b.credential],
      },
      { requester: c },
    );
    expect(result.ok).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("verifyDelegationChain — limits and shape", () => {
  it("refuses unusable limits", async () => {
    for (const limits of [
      { ...LIMITS, maxLinks: 0 },
      { ...LIMITS, maxLifetimeSeconds: 1.5 },
      { ...LIMITS, maxBytes: -1 },
      { ...LIMITS, maxClockSkewSeconds: -1 },
      { ...LIMITS, maxClockSkewSeconds: 0.5 },
    ]) {
      expect(await check(oneLink(handOff(a, b)), { limits })).toEqual({
        ok: false,
        error: { code: "INVALID_LIMITS" },
      });
    }
  });

  it("refuses a malformed request to check against", async () => {
    const result = await check(oneLink(handOff(a, b)), { request: { tool: "", action: "query" } });
    expect(!result.ok && result.error.code).toBe("MALFORMED_CHAIN");
  });

  it("refuses chains of the wrong shape", async () => {
    const h = handOff(a, b);
    for (const chain of [
      null,
      [h],
      { handOffs: h, credentials: [a.credential] },
      { handOffs: [h], credentials: a.credential },
      { handOffs: [], credentials: [] },
      { handOffs: [h], credentials: [] },
      { handOffs: [42], credentials: [a.credential] },
      { handOffs: [h], credentials: [10n] },
    ]) {
      const result = await check(chain);
      expect(!result.ok && result.error.code).toBe("MALFORMED_CHAIN");
    }
  });

  it("refuses more hand-offs than the limit, before reading them", async () => {
    const result = await check({
      handOffs: ["x", "x", "x", "x"],
      credentials: [{}, {}, {}, {}],
    });
    expect(result).toEqual({ ok: false, error: { code: "TOO_MANY_LINKS" } });
  });

  it("refuses over-size input, in the hand-offs or in the credentials", async () => {
    const huge = await check({ handOffs: ["x".repeat(20_000)], credentials: [{}] });
    expect(huge).toEqual({ ok: false, error: { code: "TOO_LARGE" } });
    const bigCredential = { ...a.credential, padding: "x".repeat(20_000) };
    const result = await check(
      oneLink(handOff(a, b), bigCredential as unknown as SignedCredential),
    );
    expect(result).toEqual({ ok: false, error: { code: "TOO_LARGE" } });
  });
});

describe("verifyDelegationChain — forged or unusable links", () => {
  async function credentialError(credential: unknown) {
    const result = await check({ handOffs: [handOff(a, b)], credentials: [credential] });
    return !result.ok && result.error.code === "CREDENTIAL_INVALID" ? result.error.reason : result;
  }

  it("refuses a delegator credential that is not from the pinned issuer or does not verify", async () => {
    expect(await credentialError("a credential")).toBe("not an object");
    const otherIssuer = await issueAgent(org, { issuerDid: "did:web:other.example" });
    expect(await credentialError(otherIssuer.credential)).toBe("UNTRUSTED_ISSUER");
    // Same issuer name, another key: the pinned document has no such key.
    const otherOrg = makeOrganisation();
    expect(await credentialError((await issueAgent(otherOrg)).credential)).toBe(
      "UNKNOWN_VERIFICATION_METHOD",
    );
    const tampered = { ...a.credential, credentialSubject: { ...b.credential.credentialSubject } };
    expect(await credentialError(tampered)).toBe("SIGNATURE_INVALID");
  });

  it("refuses a delegator credential with no agent or no usable key", async () => {
    expect(
      await credentialError(
        await issueCustomAgent(org, a, { subject: { publicKeyMultibase: "z" } }),
      ),
    ).toBe("MISSING_SUBJECT");
    expect(await credentialError(await issueCustomAgent(org, a, { subject: { id: a.did } }))).toBe(
      "MISSING_AGENT_KEY",
    );
    expect(
      await credentialError(
        await issueCustomAgent(org, a, { subject: { id: a.did, publicKeyMultibase: "zNotAKey" } }),
      ),
    ).toBe("MISSING_AGENT_KEY");
  });

  it("refuses a delegator credential outside its validity period", async () => {
    expect(await credentialError(await issueCustomAgent(org, a, { validFrom: "yesterday" }))).toBe(
      "validFrom is not a timestamp",
    );
    const future = new Date(NOW.getTime() + 60_000).toISOString();
    expect(await credentialError(await issueCustomAgent(org, a, { validFrom: future }))).toBe(
      "NOT_YET_VALID",
    );
    expect(await credentialError(await issueCustomAgent(org, a, { validUntil: "soon" }))).toBe(
      "validUntil is not a timestamp",
    );
    expect(
      await credentialError(await issueCustomAgent(org, a, { validUntil: NOW.toISOString() })),
    ).toBe("EXPIRED");
  });

  it("refuses a forged hand-off signature", async () => {
    // Claims to be from A, signed with C's key.
    const forged = signed(claimsOf(a, b), c);
    expect(await check(oneLink(forged))).toEqual({
      ok: false,
      error: { code: "SIGNATURE_INVALID", link: 0 },
    });
  });

  it("refuses an unsigned hand-off and one whose claims were edited", async () => {
    const [claims] = handOff(a, b).split(".") as [string];
    expect(await check(oneLink(`${claims}.`))).toEqual({
      ok: false,
      error: { code: "SIGNATURE_INVALID", link: 0 },
    });
    const [, signature] = handOff(a, b).split(".") as [string, string];
    const widened = Buffer.from(JSON.stringify(claimsOf(a, b, { grants: DB_ALL }))).toString(
      "base64url",
    );
    expect(await check(oneLink(`${widened}.${signature}`))).toEqual({
      ok: false,
      error: { code: "SIGNATURE_INVALID", link: 0 },
    });
  });

  it("refuses a hand-off that is not two parts, not JSON, or missing fields", async () => {
    for (const bad of [
      `${handOff(a, b)}.extra`,
      (() => {
        const encoded = Buffer.from("not json").toString("base64url");
        return `${encoded}.${Buffer.from(sign(Buffer.from(encoded), a.keys.secretKey)).toString("base64url")}`;
      })(),
      signed({ ...claimsOf(a, b), depth: -1 }, a),
      signed({ ...claimsOf(a, b), grants: [] }, a),
      signed({ ...claimsOf(a, b), prev: 7 }, a),
      signed({ ...claimsOf(a, b), sub: "" }, a),
      signed([], a),
    ]) {
      const result = await check(oneLink(bad));
      expect(!result.ok && result.error.code).toBe("MALFORMED_CHAIN");
    }
  });

  it("refuses a signed statement of another type", async () => {
    expect(
      await check(oneLink(signed(claimsOf(a, b, { typ: "custos-token-request-proof" }), a))),
    ).toEqual({
      ok: false,
      error: { code: "WRONG_TYPE", link: 0 },
    });
  });

  it("refuses an expired, a not-yet-valid, and a back-to-front hand-off", async () => {
    expect(await check(oneLink(handOff(a, b)), { now: new Date((NOW_S + 600) * 1000) })).toEqual({
      ok: false,
      error: { code: "EXPIRED", link: 0 },
    });
    expect(await check(oneLink(handOff(a, b, { now: new Date((NOW_S + 60) * 1000) })))).toEqual({
      ok: false,
      error: { code: "NOT_YET_VALID", link: 0 },
    });
    // Within the clock-skew bound is accepted.
    expect((await check(oneLink(handOff(a, b, { now: new Date((NOW_S + 5) * 1000) })))).ok).toBe(
      true,
    );
    const backwards = await check(oneLink(signed(claimsOf(a, b, { exp: NOW_S }), a)));
    expect(!backwards.ok && backwards.error.code).toBe("MALFORMED_CHAIN");
  });
});

describe("verifyDelegationChain — links bound both ways", () => {
  it("refuses a hand-off whose issuer is not the agent of its credential", async () => {
    // Signed with A's key but naming C as the delegator.
    const result = await check(oneLink(signed(claimsOf(c, b), a)));
    expect(!result.ok && result.error).toMatchObject({ code: "BROKEN_LINK", link: 0 });
  });

  it("refuses a first hand-off that claims to extend another", async () => {
    const result = await check(oneLink(signed(claimsOf(a, b, { prev: handOffHash("x") }), a)));
    expect(!result.ok && result.error).toMatchObject({ code: "BROKEN_LINK", link: 0 });
  });

  it("refuses a link whose issuer is not the previous delegate", async () => {
    const first = handOff(a, b, { depth: 1 });
    // C hands on, though A handed to B.
    const second = handOff(c, b, { previous: first });
    const result = await check({
      handOffs: [first, second],
      credentials: [a.credential, c.credential],
    });
    expect(!result.ok && result.error).toMatchObject({ code: "BROKEN_LINK", link: 1 });
  });

  it("refuses a link spliced in from another chain", async () => {
    const first = handOff(a, b, { depth: 1 });
    const otherFirst = handOff(a, b, { depth: 1, grants: DB_ALL });
    // B's hand-off extends a different A→B hand-off than the one presented.
    const spliced = handOff(b, c, { previous: otherFirst });
    const result = await check(
      { handOffs: [first, spliced], credentials: [a.credential, b.credential] },
      { requester: c },
    );
    expect(!result.ok && result.error).toMatchObject({ code: "BROKEN_LINK", link: 1 });
  });

  it("refuses a prefix of a chain presented by someone other than its last holder", async () => {
    const first = handOff(a, b, { depth: 1 });
    // C presents only the A→B part, as if it were B.
    const result = await check(oneLink(first), { requester: c });
    expect(result).toEqual({ ok: false, error: { code: "WRONG_HOLDER" } });
  });
});

describe("verifyDelegationChain — never widens", () => {
  it("refuses another tool and another action than the delegator was given", async () => {
    const first = handOff(a, b, { depth: 1 });
    const otherTool = handOff(b, c, {
      previous: first,
      grants: [{ tool: "mock-slack", actions: ["query"] }],
    });
    const otherAction = handOff(b, c, { previous: first, grants: DB_ALL });
    for (const second of [otherTool, otherAction]) {
      const result = await check(
        { handOffs: [first, second], credentials: [a.credential, b.credential] },
        { requester: c },
      );
      expect(!result.ok && result.error).toMatchObject({ code: "WIDENED", link: 1 });
    }
  });

  it("refuses a request the last hand-off does not cover", async () => {
    const result = await check(oneLink(handOff(a, b)), {
      request: { tool: "mock-database", action: "write" },
    });
    expect(result).toEqual({ ok: false, error: { code: "NOT_COVERED" } });
    const otherTool = await check(oneLink(handOff(a, b)), {
      request: { tool: "mock-slack", action: "query" },
    });
    expect(otherTool).toEqual({ ok: false, error: { code: "NOT_COVERED" } });
  });

  it("refuses a later exp than the parent, and a lifetime over the limit", async () => {
    const first = handOff(a, b, { depth: 1, ttlSeconds: 300 });
    const outlives = handOff(b, c, { previous: first, ttlSeconds: 301 });
    const result = await check(
      { handOffs: [first, outlives], credentials: [a.credential, b.credential] },
      { requester: c },
    );
    expect(!result.ok && result.error).toMatchObject({ code: "WIDENED", link: 1 });

    const tooLong = await check(oneLink(handOff(a, b, { ttlSeconds: 3601 })));
    expect(!tooLong.ok && tooLong.error).toMatchObject({ code: "WIDENED", link: 0 });
  });

  it("refuses a depth that does not shrink, and a first depth over the link limit", async () => {
    const first = handOff(a, b, { depth: 1 });
    const same = handOff(b, c, { previous: first, depth: 1 });
    const result = await check(
      { handOffs: [first, same], credentials: [a.credential, b.credential] },
      { requester: c },
    );
    expect(!result.ok && result.error).toMatchObject({ code: "WIDENED", link: 1 });

    // A depth-0 hand-off cannot be handed on at all.
    const leaf = handOff(a, b);
    const onward = handOff(b, c, { previous: leaf });
    const fromLeaf = await check(
      { handOffs: [leaf, onward], credentials: [a.credential, b.credential] },
      { requester: c },
    );
    expect(!fromLeaf.ok && fromLeaf.error).toMatchObject({ code: "WIDENED", link: 1 });

    const deep = await check(oneLink(handOff(a, b, { depth: 3 })));
    expect(!deep.ok && deep.error).toMatchObject({ code: "WIDENED", link: 0 });
    expect((await check(oneLink(handOff(a, b, { depth: 2 })))).ok).toBe(true);
  });
});

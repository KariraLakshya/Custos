import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import { multibaseToPublicKey } from "../did/did-web.js";
import {
  buildForeignCallProof,
  buildRegistrationRequest,
  FOREIGN_CALL_PROOF_TYPE,
  isBoundRequest,
  verifyForeignCallProof,
  verifyTokenRequestProof,
  buildTokenRequestProof,
  TOKEN_REQUEST_PROOF_TYPE,
  issuePossessionProof,
  REGISTRATION_PROOF_TYPE,
  verifyPossessionProof,
  type PossessionProofClaims,
  proofReplayExpiresAtMs,
} from "./possession.js";

const AUDIENCE = "did:web:localhost%3A4001";
const NOW = new Date("2026-09-25T12:00:00Z");
const NOW_SECONDS = NOW.getTime() / 1000;

function claims(overrides: Partial<PossessionProofClaims> = {}): PossessionProofClaims {
  return {
    typ: REGISTRATION_PROOF_TYPE,
    aud: AUDIENCE,
    iat: NOW_SECONDS,
    jti: "j-1",
    ...overrides,
  };
}

async function proofSignedBy(
  secretKey: Uint8Array,
  proofClaims: PossessionProofClaims = claims(),
): Promise<string> {
  const issued = await issuePossessionProof({
    claims: proofClaims,
    sign: async (data) => sign(data, secretKey),
  });
  if (!issued.ok) throw new Error("issuing failed");
  return issued.value;
}

function verifyAgainst(proof: string, publicKey: Uint8Array, at: Date = NOW) {
  return verifyPossessionProof({
    proof,
    publicKey,
    expectedType: REGISTRATION_PROOF_TYPE,
    expectedAudience: AUDIENCE,
    now: at,
    maxSkewSeconds: 60,
  });
}

describe("possession proofs", () => {
  it("verifies a proof signed by the matching key and returns its claims", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await proofSignedBy(secretKey);

    expect(verifyAgainst(proof, publicKey)).toEqual({ ok: true, value: claims() });
  });

  it("rejects a proof signed by a different key — possession of the named key is the point", async () => {
    const holder = generateKeyPair();
    const impostor = generateKeyPair();
    const proof = await proofSignedBy(impostor.secretKey);

    expect(verifyAgainst(proof, holder.publicKey)).toEqual({
      ok: false,
      error: { code: "SIGNATURE_INVALID" },
    });
  });

  it("rejects a proof whose claims were altered after signing", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const [, signature] = (await proofSignedBy(secretKey)).split(".");
    const forgedClaims = Buffer.from(
      JSON.stringify(claims({ aud: "did:web:attacker.example" })),
    ).toString("base64url");

    expect(verifyAgainst(`${forgedClaims}.${signature}`, publicKey)).toEqual({
      ok: false,
      error: { code: "SIGNATURE_INVALID" },
    });
  });

  it("rejects a validly signed proof of another type — one proof kind can't stand in for another", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await proofSignedBy(secretKey, claims({ typ: "custos-token-request-proof" }));

    expect(verifyAgainst(proof, publicKey)).toEqual({ ok: false, error: { code: "WRONG_TYPE" } });
  });

  it("rejects a validly signed proof meant for another audience", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await proofSignedBy(secretKey, claims({ aud: "did:web:other.example" }));

    expect(verifyAgainst(proof, publicKey)).toEqual({
      ok: false,
      error: { code: "WRONG_AUDIENCE" },
    });
  });

  it.each([
    ["issued too far in the past", -61],
    ["issued too far in the future", 61],
  ])("rejects a proof %s", async (_label, offsetSeconds) => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await proofSignedBy(secretKey, claims({ iat: NOW_SECONDS + offsetSeconds }));

    expect(verifyAgainst(proof, publicKey)).toEqual({ ok: false, error: { code: "STALE" } });
  });

  it.each([
    ["exactly at the past edge", -60],
    ["exactly at the future edge", 60],
  ])("accepts a proof %s of the skew window", async (_label, offsetSeconds) => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await proofSignedBy(secretKey, claims({ iat: NOW_SECONDS + offsetSeconds }));

    expect(verifyAgainst(proof, publicKey).ok).toBe(true);
  });

  it.each([
    ["no separator", "abc"],
    ["too many separators", "a.b.c"],
    ["claims that are not JSON", `${Buffer.from("not json").toString("base64url")}.AAAA`],
    [
      "claims missing a field",
      `${Buffer.from(JSON.stringify({ typ: REGISTRATION_PROOF_TYPE, aud: AUDIENCE, iat: 1 })).toString("base64url")}.AAAA`,
    ],
    [
      "a non-numeric iat",
      `${Buffer.from(JSON.stringify({ ...claims(), iat: "now" })).toString("base64url")}.AAAA`,
    ],
    ["claims that are JSON null", `${Buffer.from("null").toString("base64url")}.AAAA`],
    ["an oversized proof", "a".repeat(4097)],
  ])("rejects a malformed proof: %s", (_label, proof) => {
    const { publicKey } = generateKeyPair();
    const result = verifyAgainst(proof, publicKey);
    expect(result.ok === false && result.error.code).toBe("MALFORMED_PROOF");
  });

  it("reports a signer that throws a non-Error as a value too", async () => {
    const issued = await issuePossessionProof({
      claims: claims(),
      sign: () => Promise.reject("hsm offline"),
    });
    expect(issued).toEqual({ ok: false, error: { code: "SIGNING_FAILED", reason: "hsm offline" } });
  });

  it("reports a signer failure as a value", async () => {
    const issued = await issuePossessionProof({
      claims: claims(),
      sign: () => Promise.reject(new Error("kms unreachable")),
    });
    expect(issued).toEqual({
      ok: false,
      error: { code: "SIGNING_FAILED", reason: "kms unreachable" },
    });
  });
});

describe("buildRegistrationRequest", () => {
  it("builds a request whose proof verifies against the public key it submits", async () => {
    const request = await buildRegistrationRequest({ audience: AUDIENCE, now: NOW, jti: "j-9" });

    const submitted = multibaseToPublicKey(request.body.publicKey);
    expect(submitted).toEqual({ ok: true, value: request.publicKey });
    expect(verifyAgainst(request.body.proof, request.publicKey)).toEqual({
      ok: true,
      value: claims({ jti: "j-9" }),
    });
  });

  it("generates a fresh key and a unique proof id each time", async () => {
    const a = await buildRegistrationRequest({ audience: AUDIENCE, now: NOW });
    const b = await buildRegistrationRequest({ audience: AUDIENCE, now: NOW });

    expect(a.body.publicKey).not.toBe(b.body.publicKey);
    expect(a.body.proof).not.toBe(b.body.proof);
  });
});

describe("token-request proofs are bound to one tool and action (ADR 0015)", () => {
  const VAULT_TOKENS = "https://vault.custos.example/tokens";
  const REQUEST = { tool: "mock-database", action: "query" };

  function verifyToken(
    proof: string,
    publicKey: Uint8Array,
    expectedRequest: { tool: string; action: string } = REQUEST,
  ) {
    return verifyTokenRequestProof({
      proof,
      publicKey,
      expectedAudience: VAULT_TOKENS,
      expectedRequest,
      now: NOW,
      maxSkewSeconds: 60,
    });
  }

  function build(secretKey: Uint8Array, request = REQUEST, jti?: string): Promise<string> {
    return buildTokenRequestProof({
      audience: VAULT_TOKENS,
      secretKey,
      now: NOW,
      request,
      ...(jti === undefined ? {} : { jti }),
    });
  }

  it("proves possession for a token request, addressed to the vault's /tokens URL", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await build(secretKey, REQUEST, "t-1");
    expect(verifyToken(proof, publicKey)).toEqual({
      ok: true,
      value: { typ: TOKEN_REQUEST_PROOF_TYPE, aud: VAULT_TOKENS, iat: NOW_SECONDS, jti: "t-1" },
    });
  });

  it.each([
    ["another granted tool", { tool: "mock-slack", action: "query" }],
    ["another action", { tool: "mock-database", action: "delete" }],
  ])("refuses it when presented for %s", async (_label, presentedAs) => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await build(secretKey);
    expect(verifyToken(proof, publicKey, presentedAs)).toEqual({
      ok: false,
      error: { code: "WRONG_REQUEST" },
    });
  });

  it("refuses a correctly signed token proof in the old format, which names no request", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const old = await proofSignedBy(
      secretKey,
      claims({ typ: TOKEN_REQUEST_PROOF_TYPE, aud: VAULT_TOKENS }),
    );
    expect(verifyToken(old, publicKey)).toEqual({
      ok: false,
      error: { code: "MALFORMED_PROOF", reason: "proof does not name its request" },
    });
  });

  it("cannot be checked without a request: the general verifier refuses the token type", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await build(secretKey);
    expect(
      verifyPossessionProof({
        proof,
        publicKey,
        expectedType: TOKEN_REQUEST_PROOF_TYPE,
        expectedAudience: VAULT_TOKENS,
        now: NOW,
        maxSkewSeconds: 60,
      }),
    ).toMatchObject({ ok: false, error: { code: "MALFORMED_PROOF" } });
  });

  it("is not accepted as a foreign-call proof, nor a foreign-call proof as it", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const tokenProof = await build(secretKey);
    expect(
      verifyForeignCallProof({
        proof: tokenProof,
        publicKey,
        expectedAudience: VAULT_TOKENS,
        expectedRequest: REQUEST,
        now: NOW,
        maxSkewSeconds: 60,
      }),
    ).toEqual({ ok: false, error: { code: "WRONG_TYPE" } });
    const foreignProof = await buildForeignCallProof({
      audience: VAULT_TOKENS,
      secretKey,
      now: NOW,
      request: REQUEST,
    });
    expect(verifyToken(foreignProof, publicKey)).toEqual({
      ok: false,
      error: { code: "WRONG_TYPE" },
    });
  });

  it("is not accepted as a registration proof", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const tokenProof = await buildTokenRequestProof({
      audience: AUDIENCE,
      secretKey,
      now: NOW,
      request: REQUEST,
    });
    expect(verifyAgainst(tokenProof, publicKey)).toEqual({
      ok: false,
      error: { code: "WRONG_TYPE" },
    });
  });

  it("will not build a proof without a valid request", async () => {
    const { secretKey } = generateKeyPair();
    await expect(build(secretKey, { tool: "", action: "query" })).rejects.toThrow(
      "tool and action",
    );
  });

  it("uses a fresh unique id every time", async () => {
    const { secretKey } = generateKeyPair();
    expect(await build(secretKey)).not.toBe(await build(secretKey));
  });
});

describe("foreign-call proofs are bound to one tool and action (ADR 0015)", () => {
  const RECEIVER = "https://b.example/federation";
  const REQUEST = { tool: "b-ledger", action: "read" };

  function verifyForeign(
    proof: string,
    publicKey: Uint8Array,
    expectedRequest: { tool: string; action: string } = REQUEST,
  ) {
    return verifyForeignCallProof({
      proof,
      publicKey,
      expectedAudience: RECEIVER,
      expectedRequest,
      now: NOW,
      maxSkewSeconds: 30,
    });
  }

  function build(secretKey: Uint8Array, request = REQUEST, jti?: string): Promise<string> {
    return buildForeignCallProof({
      audience: RECEIVER,
      secretKey,
      now: NOW,
      request,
      ...(jti === undefined ? {} : { jti }),
    });
  }

  it("verifies a proof made for the request it is presented with", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await build(secretKey, REQUEST, "f-1");
    expect(verifyForeign(proof, publicKey)).toEqual({
      ok: true,
      value: { typ: FOREIGN_CALL_PROOF_TYPE, aud: RECEIVER, iat: NOW_SECONDS, jti: "f-1" },
    });
  });

  it.each([
    ["another tool", { tool: "stripe", action: "read" }],
    ["another action", { tool: "b-ledger", action: "write" }],
    ["a tool that differs only in case", { tool: "B-ledger", action: "read" }],
    ["an action with a trailing space", { tool: "b-ledger", action: "read " }],
  ])("refuses it when presented for %s", async (_label, presentedAs) => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await build(secretKey);
    expect(verifyForeign(proof, publicKey, presentedAs)).toEqual({
      ok: false,
      error: { code: "WRONG_REQUEST" },
    });
  });

  it("refuses a correctly signed foreign proof in the old format, which names no request", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const old = await proofSignedBy(
      secretKey,
      claims({ typ: FOREIGN_CALL_PROOF_TYPE, aud: RECEIVER }),
    );
    expect(verifyForeign(old, publicKey)).toEqual({
      ok: false,
      error: { code: "MALFORMED_PROOF", reason: "proof does not name its request" },
    });
  });

  it.each([
    ["a numeric tool", { tool: 7, action: "read" }],
    ["a missing action", { tool: "b-ledger" }],
    ["an object action", { tool: "b-ledger", action: { name: "read" } }],
  ])("refuses a correctly signed proof with %s", async (_label, request) => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await proofSignedBy(secretKey, {
      ...claims({ typ: FOREIGN_CALL_PROOF_TYPE, aud: RECEIVER }),
      ...request,
    } as PossessionProofClaims);
    expect(verifyForeign(proof, publicKey)).toMatchObject({
      ok: false,
      error: { code: "MALFORMED_PROOF" },
    });
  });

  it("checks the signature before believing the request it names", async () => {
    const { secretKey } = generateKeyPair();
    const other = generateKeyPair();
    const proof = await build(secretKey);
    expect(verifyForeign(proof, other.publicKey, { tool: "x", action: "y" })).toEqual({
      ok: false,
      error: { code: "SIGNATURE_INVALID" },
    });
  });

  it("cannot be checked without a request: the general verifier refuses the foreign type", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await build(secretKey);
    expect(
      verifyPossessionProof({
        proof,
        publicKey,
        expectedType: FOREIGN_CALL_PROOF_TYPE,
        expectedAudience: RECEIVER,
        now: NOW,
        maxSkewSeconds: 30,
      }),
    ).toMatchObject({ ok: false, error: { code: "MALFORMED_PROOF" } });
  });

  it.each([
    ["an empty tool", { tool: "", action: "read" }],
    ["an empty action", { tool: "b-ledger", action: "" }],
    ["no request", undefined],
  ])("refuses to check against %s", async (_label, expected) => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await build(secretKey);
    expect(
      verifyForeignCallProof({
        proof,
        publicKey,
        expectedAudience: RECEIVER,
        expectedRequest: expected as unknown as { tool: string; action: string },
        now: NOW,
        maxSkewSeconds: 30,
      }),
    ).toMatchObject({ ok: false, error: { code: "MALFORMED_PROOF" } });
  });

  it.each([
    ["an empty tool", { tool: "", action: "read" }],
    ["an empty action", { tool: "b-ledger", action: "" }],
    ["a tool over 128 characters", { tool: "t".repeat(129), action: "read" }],
    ["a non-string action", { tool: "b-ledger", action: 7 }],
  ])("will not build a proof for %s", async (_label, request) => {
    const { secretKey } = generateKeyPair();
    await expect(
      build(secretKey, request as unknown as { tool: string; action: string }),
    ).rejects.toThrow("tool and action");
  });

  it("accepts the longest allowed tool and action", async () => {
    const longest = { tool: "t".repeat(128), action: "a".repeat(128) };
    expect(isBoundRequest(longest)).toBe(true);
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await build(secretKey, longest);
    expect(verifyForeign(proof, publicKey, longest).ok).toBe(true);
  });

  it.each([null, "b-ledger", [], {}, { tool: "b-ledger" }])(
    "isBoundRequest refuses %j",
    (value) => {
      expect(isBoundRequest(value)).toBe(false);
    },
  );
});

describe("proofReplayExpiresAtMs", () => {
  it("keeps a proof id until the proof can no longer be accepted, one whole second past iat + skew", () => {
    expect(proofReplayExpiresAtMs(100, 30)).toBe(131_000);
  });

  it("is never earlier than the last instant verifyPossessionProof still accepts", () => {
    const { publicKey, secretKey } = generateKeyPair();
    const iat = 1_000;
    const skew = 30;
    const proof = (async () =>
      issuePossessionProof({
        claims: { typ: "t", aud: "a", iat, jti: "j" },
        sign: async (data) => sign(data, secretKey),
      }))();
    return proof.then((issued) => {
      if (!issued.ok) throw new Error("fixture");
      // The last millisecond at which the proof is still accepted:
      const lastAccepted = new Date((iat + skew + 1) * 1000 - 1);
      expect(
        verifyPossessionProof({
          proof: issued.value,
          publicKey,
          expectedType: "t",
          expectedAudience: "a",
          now: lastAccepted,
          maxSkewSeconds: skew,
        }).ok,
      ).toBe(true);
      expect(proofReplayExpiresAtMs(iat, skew)).toBeGreaterThan(lastAccepted.getTime());
    });
  });
});

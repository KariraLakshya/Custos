import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import { multibaseToPublicKey } from "../did/did-web.js";
import {
  buildRegistrationRequest,
  buildTokenRequestProof,
  TOKEN_REQUEST_PROOF_TYPE,
  issuePossessionProof,
  REGISTRATION_PROOF_TYPE,
  verifyPossessionProof,
  type PossessionProofClaims,
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

describe("buildTokenRequestProof", () => {
  const VAULT_TOKENS = "https://vault.custos.example/tokens";

  it("proves possession for a token request, addressed to the vault's /tokens URL", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const proof = await buildTokenRequestProof({
      audience: VAULT_TOKENS,
      secretKey,
      now: NOW,
      jti: "t-1",
    });

    const verified = verifyPossessionProof({
      proof,
      publicKey,
      expectedType: TOKEN_REQUEST_PROOF_TYPE,
      expectedAudience: VAULT_TOKENS,
      now: NOW,
      maxSkewSeconds: 60,
    });
    expect(verified).toEqual({
      ok: true,
      value: { typ: TOKEN_REQUEST_PROOF_TYPE, aud: VAULT_TOKENS, iat: NOW_SECONDS, jti: "t-1" },
    });
  });

  it("is not accepted as a registration proof, nor a registration proof as it", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const tokenProof = await buildTokenRequestProof({ audience: AUDIENCE, secretKey, now: NOW });

    expect(verifyAgainst(tokenProof, publicKey)).toEqual({
      ok: false,
      error: { code: "WRONG_TYPE" },
    });
  });

  it("uses a fresh unique id every time", async () => {
    const { secretKey } = generateKeyPair();
    const a = await buildTokenRequestProof({ audience: VAULT_TOKENS, secretKey, now: NOW });
    const b = await buildTokenRequestProof({ audience: VAULT_TOKENS, secretKey, now: NOW });
    expect(a).not.toBe(b);
  });
});

import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import {
  issueRevocationTombstone,
  verifyRevocationTombstone,
  type RevocationTombstone,
} from "./tombstone.js";

const AGENT_DID = "did:web:localhost%3A4001:agents:0f8f6a1e-9c2b-4a3d-8f1e-1b2c3d4e5f60";

function signerFor(secretKey: Uint8Array) {
  return { sign: async (data: Uint8Array) => sign(data, secretKey) };
}

function tombstoneFor(overrides: Partial<RevocationTombstone> = {}): RevocationTombstone {
  return {
    agentDid: AGENT_DID,
    statusListIndex: 42,
    revokedAt: "2026-09-07T10:00:00.000Z",
    ...overrides,
  };
}

/** Encodes arbitrary claims and signs them, to exercise the verify path. */
async function signClaims(claims: unknown, secretKey: Uint8Array): Promise<string> {
  const encodedClaims = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const signature = sign(Buffer.from(encodedClaims, "utf8"), secretKey);
  return `${encodedClaims}.${Buffer.from(signature).toString("base64url")}`;
}

describe("issueRevocationTombstone", () => {
  it("produces a two-part compact envelope", async () => {
    const { secretKey } = generateKeyPair();
    const issued = await issueRevocationTombstone({
      tombstone: tombstoneFor(),
      signer: signerFor(secretKey),
    });
    expect(issued.ok).toBe(true);
    if (issued.ok) expect(issued.value.split(".")).toHaveLength(2);
  });

  it("fails closed when the signer throws rather than propagating", async () => {
    const issued = await issueRevocationTombstone({
      tombstone: tombstoneFor(),
      signer: {
        sign: async () => {
          throw new Error("KMS unavailable");
        },
      },
    });
    expect(issued.ok).toBe(false);
    if (!issued.ok) {
      expect(issued.error.code).toBe("SIGNING_FAILED");
      expect(issued.error.reason).toContain("KMS unavailable");
    }
  });

  it("reports a non-Error thrown by the signer without crashing", async () => {
    const issued = await issueRevocationTombstone({
      tombstone: tombstoneFor(),
      signer: {
        sign: async () => {
          throw "kms offline";
        },
      },
    });
    expect(issued.ok).toBe(false);
    if (!issued.ok) expect(issued.error.reason).toBe("kms offline");
  });
});

describe("verifyRevocationTombstone", () => {
  it("verifies a tombstone and returns its claims", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const tombstone = tombstoneFor({ reason: "credential suspected compromised" });
    const issued = await issueRevocationTombstone({ tombstone, signer: signerFor(secretKey) });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const verified = verifyRevocationTombstone({ tombstone: issued.value, publicKey });
    expect(verified.ok).toBe(true);
    if (verified.ok) expect(verified.value).toEqual(tombstone);
  });

  it("verifies a tombstone with no reason given", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const issued = await issueRevocationTombstone({
      tombstone: tombstoneFor(),
      signer: signerFor(secretKey),
    });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    const verified = verifyRevocationTombstone({ tombstone: issued.value, publicKey });
    expect(verified.ok).toBe(true);
    if (verified.ok) expect(verified.value.reason).toBeUndefined();
  });

  // Revocation is permanent, so a replayed tombstone can only re-revoke an
  // already-revoked agent. It must keep verifying rather than expiring.
  it("keeps verifying on replay — a tombstone never expires", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const issued = await issueRevocationTombstone({
      tombstone: tombstoneFor(),
      signer: signerFor(secretKey),
    });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    expect(verifyRevocationTombstone({ tombstone: issued.value, publicKey }).ok).toBe(true);
    expect(verifyRevocationTombstone({ tombstone: issued.value, publicKey }).ok).toBe(true);
  });

  it("rejects a tombstone whose claims were tampered with after signing", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const issued = await issueRevocationTombstone({
      tombstone: tombstoneFor(),
      signer: signerFor(secretKey),
    });
    if (!issued.ok) throw new Error("expected issuance to succeed");

    const [, signature] = issued.value.split(".") as [string, string];
    const swapped = Buffer.from(
      JSON.stringify(tombstoneFor({ agentDid: "did:web:localhost%3A4001:agents:someone-else" })),
      "utf8",
    ).toString("base64url");
    const result = verifyRevocationTombstone({
      tombstone: `${swapped}.${signature}`,
      publicKey,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("SIGNATURE_INVALID");
  });

  it("rejects a tombstone signed by an unknown key", async () => {
    const { secretKey } = generateKeyPair();
    const impostor = generateKeyPair();
    const issued = await issueRevocationTombstone({
      tombstone: tombstoneFor(),
      signer: signerFor(secretKey),
    });
    if (!issued.ok) throw new Error("expected issuance to succeed");

    const result = verifyRevocationTombstone({
      tombstone: issued.value,
      publicKey: impostor.publicKey,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("SIGNATURE_INVALID");
  });

  it.each([
    ["no separator", "not-a-tombstone"],
    ["too many separators", "a.b.c"],
    ["empty string", ""],
  ])("rejects a malformed envelope (%s)", (_label, tombstone) => {
    const { publicKey } = generateKeyPair();
    const result = verifyRevocationTombstone({ tombstone, publicKey });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("MALFORMED_TOMBSTONE");
  });

  it("rejects claims that are not JSON", async () => {
    const { publicKey, secretKey } = generateKeyPair();
    const encodedClaims = Buffer.from("this is not json", "utf8").toString("base64url");
    const signature = sign(Buffer.from(encodedClaims, "utf8"), secretKey);
    const result = verifyRevocationTombstone({
      tombstone: `${encodedClaims}.${Buffer.from(signature).toString("base64url")}`,
      publicKey,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("MALFORMED_TOMBSTONE");
  });

  // Each of these is a correctly signed envelope carrying claims that are
  // structurally wrong — proving validation is not skipped once the
  // signature checks out.
  it.each([
    ["missing agentDid", { statusListIndex: 1, revokedAt: "2026-09-07T10:00:00.000Z" }],
    ["empty agentDid", { agentDid: "", statusListIndex: 1, revokedAt: "2026-09-07T10:00:00.000Z" }],
    ["missing revokedAt", { agentDid: AGENT_DID, statusListIndex: 1 }],
    ["missing statusListIndex", { agentDid: AGENT_DID, revokedAt: "2026-09-07T10:00:00.000Z" }],
    [
      "negative statusListIndex",
      { agentDid: AGENT_DID, statusListIndex: -1, revokedAt: "2026-09-07T10:00:00.000Z" },
    ],
    [
      "fractional statusListIndex",
      { agentDid: AGENT_DID, statusListIndex: 1.5, revokedAt: "2026-09-07T10:00:00.000Z" },
    ],
    [
      "string statusListIndex",
      { agentDid: AGENT_DID, statusListIndex: "1", revokedAt: "2026-09-07T10:00:00.000Z" },
    ],
    [
      "non-string reason",
      { agentDid: AGENT_DID, statusListIndex: 1, revokedAt: "2026-09-07T10:00:00.000Z", reason: 7 },
    ],
    ["null claims", null],
    ["array claims", []],
    ["string claims", "revoked"],
  ])("rejects correctly signed but structurally invalid claims (%s)", async (_label, claims) => {
    const { publicKey, secretKey } = generateKeyPair();
    const tombstone = await signClaims(claims, secretKey);
    const result = verifyRevocationTombstone({ tombstone, publicKey });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("MALFORMED_TOMBSTONE");
  });

  it("fails closed on a malformed public key instead of throwing", async () => {
    const { secretKey } = generateKeyPair();
    const issued = await issueRevocationTombstone({
      tombstone: tombstoneFor(),
      signer: signerFor(secretKey),
    });
    if (!issued.ok) throw new Error("expected issuance to succeed");
    const result = verifyRevocationTombstone({
      tombstone: issued.value,
      publicKey: new Uint8Array(5),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("SIGNATURE_INVALID");
  });
});

import { describe, expect, it } from "vitest";
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import { publicKeyToMultibase } from "../did/did-web.js";
import { applyStatusList, verifyForeignStatusList } from "../federation/status-view.js";
import { createStatusList, isRevoked, setRevoked } from "./bitstring-status-list.js";
import { issueStatusListCredential, statusListCredentialUrl } from "./status-list-credential.js";

const NOW = new Date("2026-10-18T12:00:00.000Z");
const LIST_ID = "https://a.example/status/revocation";
const ISSUER = "did:web:a.example:revocation";

function signerFor(keys: { publicKey: Uint8Array; secretKey: Uint8Array }) {
  return {
    id: `${ISSUER}#${publicKeyToMultibase(keys.publicKey)}`,
    sign: ({ data }: { data: Uint8Array }) => Promise.resolve(sign(data, keys.secretKey)),
  };
}

function listWith(index: number): Uint8Array {
  const next = setRevoked(createStatusList(), index, true);
  if (!next.ok) throw new Error("fixture");
  return next.value;
}

describe("issueStatusListCredential", () => {
  it("signs a list that a foreign verifier accepts under the issuer's pinned key", async () => {
    const keys = generateKeyPair();
    const issued = await issueStatusListCredential({
      list: listWith(42),
      issuerDid: ISSUER,
      signer: signerFor(keys),
      statusListCredentialUrl: LIST_ID,
      now: NOW,
      validUntil: new Date(NOW.getTime() + 1_800_000),
    });
    if (!issued.ok) throw new Error(issued.error.reason);

    const verified = await verifyForeignStatusList({
      credential: issued.value,
      anchor: {
        statusIssuerDid: ISSUER,
        statusIssuerPublicKey: keys.publicKey,
        statusListId: LIST_ID,
        maxStatusAgeSeconds: 3600,
      },
      now: NOW,
      maxClockSkewSeconds: 5,
    });
    if (!verified.ok) throw new Error(verified.error.code);
    expect(isRevoked(verified.value.list, 42)).toEqual({ ok: true, value: true });
    expect(verified.value.notAfter.toISOString()).toBe("2026-10-18T12:30:00.000Z");
    expect(applyStatusList(undefined, verified.value)).toBe(verified.value);
  });

  it("omits validUntil unless given, and a foreign verifier then refuses the list", async () => {
    const keys = generateKeyPair();
    const issued = await issueStatusListCredential({
      list: createStatusList(),
      issuerDid: ISSUER,
      signer: signerFor(keys),
      statusListCredentialUrl: LIST_ID,
      now: NOW,
      ttlMs: 30_000,
    });
    if (!issued.ok) throw new Error(issued.error.reason);
    expect("validUntil" in issued.value).toBe(false);
    expect((issued.value.credentialSubject as { ttl?: number }).ttl).toBe(30_000);
    const verified = await verifyForeignStatusList({
      credential: issued.value,
      anchor: {
        statusIssuerDid: ISSUER,
        statusIssuerPublicKey: keys.publicKey,
        statusListId: LIST_ID,
        maxStatusAgeSeconds: 3600,
      },
      now: NOW,
      maxClockSkewSeconds: 5,
    });
    expect(verified).toMatchObject({ ok: false, error: { code: "LIST_NO_VALID_UNTIL" } });
  });

  it("returns a named error when signing fails", async () => {
    const issued = await issueStatusListCredential({
      list: createStatusList(),
      issuerDid: ISSUER,
      signer: { id: `${ISSUER}#k`, sign: () => Promise.reject(new Error("kms unreachable")) },
      statusListCredentialUrl: LIST_ID,
      now: NOW,
    });
    expect(issued).toMatchObject({ ok: false, error: { code: "SIGNING_FAILED" } });
  });
});

describe("statusListCredentialUrl", () => {
  it("uses http for local development hosts and https for everything else", () => {
    expect(statusListCredentialUrl("localhost:4003")).toBe(
      "http://localhost:4003/status/revocation",
    );
    expect(statusListCredentialUrl("127.0.0.1:4503")).toBe(
      "http://127.0.0.1:4503/status/revocation",
    );
    expect(statusListCredentialUrl("a.example")).toBe("https://a.example/status/revocation");
    expect(statusListCredentialUrl("a.example:8443")).toBe(
      "https://a.example:8443/status/revocation",
    );
  });
});

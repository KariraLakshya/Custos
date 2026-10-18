import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../crypto/ed25519.js";
import { encodeStatusList, createStatusList, isRevoked } from "../status/bitstring-status-list.js";
import type { SignedCredential } from "../vc/credential.js";
import { issueList, makeOrganisation, NOW, type Draft, sub } from "./fixtures.js";
import {
  applyStatusList,
  verifyForeignStatusList,
  type VerifiedForeignStatusList,
} from "./status-view.js";

const SKEW = 5;

async function verify(
  credential: unknown,
  org = makeOrganisation(),
  now = NOW,
): ReturnType<typeof verifyForeignStatusList> {
  return verifyForeignStatusList({
    credential,
    anchor: org.anchor,
    now,
    maxClockSkewSeconds: SKEW,
  });
}

function mutate(credential: SignedCredential, change: (draft: Draft) => void): unknown {
  const draft = structuredClone(credential) as unknown as Draft;
  change(draft);
  return draft;
}

async function accepted(
  list: Promise<SignedCredential>,
  org = makeOrganisation(),
): Promise<VerifiedForeignStatusList> {
  const result = await verify(await list, org);
  if (!result.ok) throw new Error(`expected a valid list, got ${result.error.code}`);
  return result.value;
}

describe("verifyForeignStatusList", () => {
  it("accepts a list signed by the pinned status key and reads its bits", async () => {
    const org = makeOrganisation();
    const view = await accepted(issueList(org, { revoked: [3, 9] }), org);
    expect(isRevoked(view.list, 3)).toEqual({ ok: true, value: true });
    expect(isRevoked(view.list, 4)).toEqual({ ok: true, value: false });
    expect(view.validFrom.toISOString()).toBe("2026-10-17T11:59:50.000Z");
  });

  it("bounds acceptance by the earlier of validUntil and validFrom + the anchor's window", async () => {
    const orgShortWindow = makeOrganisation({ maxStatusAgeSeconds: 60 });
    const a = await accepted(issueList(orgShortWindow), orgShortWindow);
    expect(a.notAfter.toISOString()).toBe("2026-10-17T12:00:50.000Z"); // validFrom + 60 s

    const org = makeOrganisation();
    const b = await accepted(
      issueList(org, { validUntil: new Date("2026-10-17T12:10:00.000Z") }),
      org,
    );
    expect(b.notAfter.toISOString()).toBe("2026-10-17T12:10:00.000Z"); // validUntil
  });

  it("fails closed on an anchor with an unusable window", async () => {
    for (const maxStatusAgeSeconds of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      const org = makeOrganisation({ maxStatusAgeSeconds });
      const result = await verify(await issueList(org), org);
      expect(result).toMatchObject({ ok: false, error: { code: "ANCHOR_INVALID" } });
    }
  });

  it("refuses input that is not a reasonable object", async () => {
    for (const input of [null, undefined, "x", 42, [], true]) {
      expect(await verify(input)).toMatchObject({ ok: false, error: { code: "LIST_MALFORMED" } });
    }
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(await verify(cyclic)).toMatchObject({ ok: false, error: { code: "LIST_MALFORMED" } });
    expect(await verify({ junk: "x".repeat(1_100_000) })).toMatchObject({
      ok: false,
      error: { code: "LIST_MALFORMED" },
    });
  });

  it("refuses a list from another issuer or with another id before checking any signature", async () => {
    const org = makeOrganisation();
    const list = await issueList(org);
    expect(
      await verify(
        mutate(list, (d) => (d.issuer = "did:web:evil.example")),
        org,
      ),
    ).toMatchObject({
      error: { code: "LIST_WRONG_ISSUER" },
    });
    expect(
      await verify(
        mutate(list, (d) => (d.id = "https://evil.example/list")),
        org,
      ),
    ).toMatchObject({
      error: { code: "LIST_WRONG_ID" },
    });
  });

  it("refuses a list signed by a key that is not the pinned status key", async () => {
    const org = makeOrganisation();
    const forged = await issueList(org, { signWith: generateKeyPair() });
    expect(await verify(forged, org)).toMatchObject({
      ok: false,
      error: { code: "LIST_SIGNATURE_INVALID" },
    });
  });

  it("refuses a list signed by the organisation's identity key (a different key)", async () => {
    const org = makeOrganisation();
    const wrongRole = await issueList(org, { signWith: org.identityKeys });
    expect(await verify(wrongRole, org)).toMatchObject({
      error: { code: "LIST_SIGNATURE_INVALID" },
    });
  });

  describe("the signature covers every field the decision relies on", () => {
    it.each([
      ["validUntil", (d: Draft) => (d.validUntil = "2099-01-01T00:00:00.000Z")],
      ["validUntil removed", (d: Draft) => delete d.validUntil],
      ["validFrom", (d: Draft) => (d.validFrom = "2026-10-17T11:59:59.000Z")],
      ["encodedList", (d: Draft) => (sub(d).encodedList = encodeStatusList(createStatusList()))],
      ["statusPurpose", (d: Draft) => (sub(d).statusPurpose = "suspension")],
      ["subject type", (d: Draft) => (sub(d).type = "Other")],
      ["credential type", (d: Draft) => (d.type = ["VerifiableCredential"])],
      ["subject id", (d: Draft) => (sub(d).id = "https://evil.example#list")],
    ])("rejects a tampered %s", async (_field, change) => {
      const org = makeOrganisation();
      const list = await issueList(org, { revoked: [3] });
      const result = await verify(mutate(list, change), org);
      expect(result).toMatchObject({ ok: false, error: { code: "LIST_SIGNATURE_INVALID" } });
    });

    it("rejects an added field that the signature does not cover", async () => {
      const org = makeOrganisation();
      const list = await issueList(org);
      const result = await verify(
        mutate(list, (d) => (d.validUntil2 = "x")),
        org,
      );
      // An unknown term must not be silently ignored by the signature check.
      expect(result.ok).toBe(false);
    });
  });

  it("refuses a correctly signed list that is not a revocation list", async () => {
    const org = makeOrganisation();
    for (const options of [
      { types: ["VerifiableCredential"] },
      { purpose: "suspension" as const },
    ]) {
      expect(await verify(await issueList(org, options), org)).toMatchObject({
        error: { code: "LIST_NOT_A_REVOCATION_LIST" },
      });
    }
  });

  it("refuses a list with no validUntil: the publisher must commit to its own freshness", async () => {
    const org = makeOrganisation();
    expect(await verify(await issueList(org, { validUntil: null }), org)).toMatchObject({
      error: { code: "LIST_NO_VALID_UNTIL" },
    });
  });

  it("refuses unreadable or inconsistent times instead of treating them as absent", async () => {
    const org = makeOrganisation();
    for (const [label, options] of [
      ["validUntil before validFrom", { validUntil: new Date(NOW.getTime() - 3_600_000) }],
    ] as const) {
      expect(await verify(await issueList(org, options), org), label).toMatchObject({
        error: { code: "LIST_MALFORMED" },
      });
    }
    // Unreadable values cannot be produced through the signer's own date types, so
    // sign them directly: the checks must hold for any correctly signed list.
    const { issueCredential } = await import("../vc/credential.js");
    const { publicKeyToMultibase } = await import("../did/did-web.js");
    const { sign } = await import("../crypto/ed25519.js");
    const { buildStatusListSubject } = await import("../status/bitstring-status-list.js");
    for (const [validFrom, validUntil] of [
      ["yesterday", "2026-10-17T12:30:00.000Z"],
      ["2026-10-17T11:59:50.000Z", "tomorrow"],
      ["2026-10-17", "2026-10-18"],
    ] as const) {
      const issued = await issueCredential({
        unsignedCredential: {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          id: org.anchor.statusListId,
          type: ["VerifiableCredential", "BitstringStatusListCredential"],
          issuer: org.statusDid,
          validFrom,
          validUntil,
          credentialSubject: {
            ...buildStatusListSubject({
              id: `${org.anchor.statusListId}#list`,
              list: createStatusList(),
            }),
          },
        },
        signer: {
          id: `${org.statusDid}#${publicKeyToMultibase(org.statusKeys.publicKey)}`,
          sign: ({ data }) => Promise.resolve(sign(data, org.statusKeys.secretKey)),
        },
      });
      if (!issued.ok) throw new Error("fixture: " + issued.error.reason);
      expect(await verify(issued.value, org), `${validFrom} / ${validUntil}`).toMatchObject({
        error: { code: "LIST_MALFORMED" },
      });
    }
  });

  it("refuses a list whose bitstring cannot be decoded", async () => {
    const org = makeOrganisation();
    const { issueCredential } = await import("../vc/credential.js");
    const { publicKeyToMultibase } = await import("../did/did-web.js");
    const { sign } = await import("../crypto/ed25519.js");
    const issued = await issueCredential({
      unsignedCredential: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: org.anchor.statusListId,
        type: ["VerifiableCredential", "BitstringStatusListCredential"],
        issuer: org.statusDid,
        validFrom: "2026-10-17T11:59:50.000Z",
        validUntil: "2026-10-17T12:30:00.000Z",
        credentialSubject: {
          id: `${org.anchor.statusListId}#list`,
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList: "uNOT-GZIP-AT-ALL",
        },
      },
      signer: {
        id: `${org.statusDid}#${publicKeyToMultibase(org.statusKeys.publicKey)}`,
        sign: ({ data }) => Promise.resolve(sign(data, org.statusKeys.secretKey)),
      },
    });
    if (!issued.ok) throw new Error("fixture: " + issued.error.reason);
    expect(await verify(issued.value, org)).toMatchObject({ error: { code: "LIST_MALFORMED" } });
  });

  it("refuses a list dated in the future beyond the allowed skew, and accepts one within it", async () => {
    const org = makeOrganisation();
    const ahead = (seconds: number) => new Date(NOW.getTime() + seconds * 1000);
    expect(await verify(await issueList(org, { validFrom: ahead(SKEW + 1) }), org)).toMatchObject({
      error: { code: "LIST_FUTURE_DATED" },
    });
    expect((await verify(await issueList(org, { validFrom: ahead(SKEW) }), org)).ok).toBe(true);
  });

  it("refuses a list older than the window, and one past its own validUntil", async () => {
    const org = makeOrganisation({ maxStatusAgeSeconds: 60 });
    const old = await issueList(org, { validFrom: new Date(NOW.getTime() - 60_000) });
    expect(await verify(old, org)).toMatchObject({ error: { code: "LIST_STALE" } }); // boundary: exactly 60 s
    const justInside = await issueList(org, { validFrom: new Date(NOW.getTime() - 59_000) });
    expect((await verify(justInside, org)).ok).toBe(true);

    const org2 = makeOrganisation();
    const expired = await issueList(org2, {
      validFrom: new Date(NOW.getTime() - 120_000),
      validUntil: new Date(NOW.getTime() - 1_000),
    });
    expect(await verify(expired, org2)).toMatchObject({ error: { code: "LIST_STALE" } });
  });
});

describe("applyStatusList: lists of different anchors", () => {
  it("carries the anchor's list id and refuses to merge two different lists", async () => {
    const org = makeOrganisation();
    const other = makeOrganisation({ statusListId: "https://c.example/status/revocation" });
    const a = await accepted(issueList(org), org);
    const c = await accepted(
      issueList(other, { id: "https://c.example/status/revocation" }),
      other,
    );
    expect(a.statusListId).toBe(org.anchor.statusListId);
    expect(c.statusListId).toBe("https://c.example/status/revocation");
    expect(() => applyStatusList(a, c)).toThrow("different anchors");
  });
});

describe("applyStatusList", () => {
  it("returns the new list when there is nothing before it", async () => {
    const org = makeOrganisation();
    const view = await accepted(issueList(org, { revoked: [1] }), org);
    expect(applyStatusList(undefined, view)).toBe(view);
  });

  it("unions revocations and never clears one, in either order", async () => {
    const org = makeOrganisation();
    const early = await accepted(
      issueList(org, { revoked: [1, 2], validFrom: new Date(NOW.getTime() - 20_000) }),
      org,
    );
    const late = await accepted(issueList(org, { revoked: [2, 3] }), org);
    for (const merged of [applyStatusList(early, late), applyStatusList(late, early)]) {
      for (const index of [1, 2, 3]) {
        expect(isRevoked(merged.list, index)).toEqual({ ok: true, value: true });
      }
      expect(isRevoked(merged.list, 4)).toEqual({ ok: true, value: false });
    }
  });

  it("never moves freshness backwards when an older list is replayed", async () => {
    const org = makeOrganisation();
    const old = await accepted(
      issueList(org, { validFrom: new Date(NOW.getTime() - 50_000) }),
      org,
    );
    const current = await accepted(issueList(org), org);
    const afterReplay = applyStatusList(current, old);
    expect(afterReplay.validFrom).toEqual(current.validFrom);
    expect(afterReplay.notAfter).toEqual(current.notAfter);
    const advanced = applyStatusList(old, current);
    expect(advanced.validFrom).toEqual(current.validFrom);
  });

  it("handles lists of different lengths", () => {
    const view = (bytes: number[], from: number): VerifiedForeignStatusList =>
      ({
        statusListId: "https://a.example/status/revocation",
        list: Uint8Array.from(bytes),
        validFrom: new Date(from),
        notAfter: new Date(from + 1000),
      }) as VerifiedForeignStatusList;
    const merged = applyStatusList(view([0b1000_0000], 1), view([0, 0, 0b0000_0001], 2));
    expect([...merged.list]).toEqual([0b1000_0000, 0, 0b0000_0001]);
    const reversed = applyStatusList(view([0, 0, 0b0000_0001], 2), view([0b1000_0000], 1));
    expect([...reversed.list]).toEqual([0b1000_0000, 0, 0b0000_0001]);
  });
});

describe("verifyForeignStatusList: acceptStale", () => {
  it("still refuses a stale list by default, but with acceptStale returns its bits and a notAfter in the past", async () => {
    const org = makeOrganisation({ maxStatusAgeSeconds: 60 });
    const old = await issueList(org, {
      revoked: [5],
      validFrom: new Date(NOW.getTime() - 3_600_000),
    });
    expect(await verify(old, org)).toMatchObject({ error: { code: "LIST_STALE" } });

    const result = await verifyForeignStatusList({
      credential: old,
      anchor: org.anchor,
      now: NOW,
      maxClockSkewSeconds: SKEW,
      acceptStale: true,
    });
    if (!result.ok) throw new Error(result.error.code);
    expect(isRevoked(result.value.list, 5)).toEqual({ ok: true, value: true });
    expect(result.value.notAfter.getTime()).toBeLessThan(NOW.getTime());
  });

  it("does not relax any other check: a forged or tampered stale list is still refused", async () => {
    const org = makeOrganisation({ maxStatusAgeSeconds: 60 });
    const accept = (credential: unknown) =>
      verifyForeignStatusList({
        credential,
        anchor: org.anchor,
        now: NOW,
        maxClockSkewSeconds: SKEW,
        acceptStale: true,
      });
    const old = new Date(NOW.getTime() - 3_600_000);
    const forged = await issueList(org, { signWith: generateKeyPair(), validFrom: old });
    expect(await accept(forged)).toMatchObject({ error: { code: "LIST_SIGNATURE_INVALID" } });
    const tampered = mutate(await issueList(org, { validFrom: old }), (d) => {
      sub(d).statusPurpose = "suspension";
    });
    expect(await accept(tampered)).toMatchObject({ error: { code: "LIST_SIGNATURE_INVALID" } });
    const noUntil = await issueList(org, { validUntil: null, validFrom: old });
    expect(await accept(noUntil)).toMatchObject({ error: { code: "LIST_NO_VALID_UNTIL" } });
    const future = await issueList(org, { validFrom: new Date(NOW.getTime() + 60_000) });
    expect(await accept(future)).toMatchObject({ error: { code: "LIST_FUTURE_DATED" } });
  });
});

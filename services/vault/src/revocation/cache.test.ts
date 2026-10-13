import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  buildDidWebDocument,
  buildStatusListEntry,
  buildStatusListSubject,
  createStatusList,
  generateKeyPair,
  issueCredential,
  issueRevocationTombstone,
  setRevoked,
  sign,
  type DidWebDocument,
  type SignedCredential,
} from "@custos/core";
import { describe, expect, it, vi } from "vitest";
import { createRevocationCache, statusListUrlFor, TRACKED_AGENT_RETENTION_MS } from "./cache.js";

const ISSUER_DID = "did:web:127.0.0.1%3A4503";
const ISSUER_DID_URL = "http://127.0.0.1:4503/.well-known/did.json";
const REVOCATION_URL = "http://127.0.0.1:4503";
const LIST_URL = "http://127.0.0.1:4503/status/revocation";
const AGENT = "did:web:127.0.0.1%3A4001:agents:11111111-1111-4111-8111-111111111111";
const OTHER_AGENT = "did:web:127.0.0.1%3A4001:agents:22222222-2222-4222-8222-222222222222";
const NOW = new Date("2026-09-07T10:00:00.000Z");
const at = (offsetMs: number): Date => new Date(NOW.getTime() + offsetMs);

function issuer() {
  const keyPair = generateKeyPair();
  const didDocument = buildDidWebDocument({
    domain: "127.0.0.1:4503",
    publicKey: keyPair.publicKey,
  });
  return {
    didDocument,
    signer: { sign: async (data: Uint8Array) => sign(data, keyPair.secretKey) },
    credentialSigner: {
      id: didDocument.verificationMethod[0].id,
      sign: async (input: { readonly data: Uint8Array }) => sign(input.data, keyPair.secretKey),
    },
  };
}

type Issuer = ReturnType<typeof issuer>;

async function tombstoneFor(signer: Issuer["signer"], agentDid = AGENT, statusListIndex = 42) {
  const issued = await issueRevocationTombstone({
    tombstone: { agentDid, statusListIndex, revokedAt: NOW.toISOString() },
    signer,
  });
  if (!issued.ok) throw new Error("expected tombstone issuance to succeed");
  return issued.value;
}

/** A signed status list, shaped the way the revocation service publishes it. */
async function listFrom(
  who: Issuer,
  options: {
    readonly revoked?: readonly number[];
    readonly validFrom?: Date;
    readonly issuerDid?: string;
    readonly id?: string;
    readonly purpose?: "revocation" | "suspension";
    readonly type?: string[];
    readonly entries?: number;
  } = {},
): Promise<SignedCredential> {
  let list = createStatusList(options.entries);
  for (const index of options.revoked ?? []) {
    const updated = setRevoked(list, index, true);
    if (!updated.ok) throw new Error("index out of range");
    list = updated.value;
  }
  const issued = await issueCredential({
    unsignedCredential: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: options.id ?? LIST_URL,
      type: options.type ?? ["VerifiableCredential", BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
      issuer: options.issuerDid ?? ISSUER_DID,
      validFrom: (options.validFrom ?? NOW).toISOString(),
      credentialSubject: {
        ...buildStatusListSubject({
          id: `${LIST_URL}#list`,
          list,
          ...(options.purpose === undefined ? {} : { statusPurpose: options.purpose }),
        }),
      },
    },
    signer: who.credentialSigner,
  });
  if (!issued.ok) throw new Error("expected list issuance to succeed");
  return issued.value;
}

const entryFor = (index: number | string, overrides: Record<string, unknown> = {}) => ({
  ...buildStatusListEntry({ statusListCredential: LIST_URL, statusListIndex: 0 }),
  statusListIndex: String(index),
  ...overrides,
});

/** Serves the issuer's DID document and, optionally, the current status list. */
function fetchServing(
  didDocument: DidWebDocument,
  list?: () => SignedCredential | Promise<SignedCredential>,
) {
  return vi.fn(async (url: string | URL) => {
    const href = String(url);
    if (href === ISSUER_DID_URL) return Response.json(didDocument);
    if (href === `${REVOCATION_URL}/status/revocation` && list) return Response.json(await list());
    return new Response(null, { status: 404 });
  });
}

function cacheWith(
  fetchImpl: unknown,
  overrides: {
    readonly maxStalenessMs?: number;
    readonly maxClockSkewMs?: number;
    readonly onRevoked?: (did: string) => Promise<void>;
  } = {},
) {
  return createRevocationCache({
    issuerDid: ISSUER_DID,
    revocationUrl: REVOCATION_URL,
    maxStalenessMs: overrides.maxStalenessMs ?? 30_000,
    // Exact boundaries unless a test is about skew.
    maxClockSkewMs: overrides.maxClockSkewMs ?? 0,
    fetchImpl: fetchImpl as typeof fetch,
    ...(overrides.onRevoked ? { onRevoked: overrides.onRevoked } : {}),
  });
}

/** A cache that has applied one list and tracks AGENT at the given index. */
async function cacheWithList(revoked: readonly number[], agentIndex: number) {
  const who = issuer();
  const cache = cacheWith(fetchServing(who.didDocument, () => listFrom(who, { revoked })));
  expect(cache.trackAgent(AGENT, entryFor(agentIndex), NOW).ok).toBe(true);
  expect((await cache.resync(NOW)).ok).toBe(true);
  return { cache, who };
}

describe("revocation cache", () => {
  describe("accepting a pushed tombstone", () => {
    it("marks the agent revoked once the tombstone verifies", async () => {
      const { didDocument, signer } = issuer();
      const cache = cacheWith(fetchServing(didDocument));
      expect(cache.verdict(AGENT)).toBe("unknown");

      const result = await cache.acceptTombstone(await tombstoneFor(signer), NOW);

      expect(result.ok).toBe(true);
      expect(cache.verdict(AGENT)).toBe("revoked");
      expect(cache.verdict(OTHER_AGENT)).toBe("unknown");
    });

    it("rejects a tombstone signed by a key that is not the revocation service's", async () => {
      const { didDocument } = issuer();
      const cache = cacheWith(fetchServing(didDocument));

      const result = await cache.acceptTombstone(await tombstoneFor(issuer().signer), NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("INVALID_TOMBSTONE");
      expect(cache.verdict(AGENT)).toBe("unknown");
    });

    it("rejects a structurally malformed tombstone", async () => {
      const cache = cacheWith(fetchServing(issuer().didDocument));

      const result = await cache.acceptTombstone("not-a-tombstone", NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("INVALID_TOMBSTONE");
    });

    it("fails closed when the issuer's DID document cannot be resolved", async () => {
      const { signer } = issuer();
      const cache = cacheWith(async () => new Response(null, { status: 503 }));

      const result = await cache.acceptTombstone(await tombstoneFor(signer), NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("UNVERIFIABLE_ISSUER");
      expect(cache.verdict(AGENT)).toBe("unknown");
    });

    it("fails closed when the issuer's document has no usable verification method", async () => {
      const { signer, didDocument } = issuer();
      const broken = { ...didDocument, verificationMethod: [] };
      const cache = cacheWith(fetchServing(broken as unknown as DidWebDocument));

      const result = await cache.acceptTombstone(await tombstoneFor(signer), NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("UNVERIFIABLE_ISSUER");
    });

    it("resolves the issuer key once and reuses it", async () => {
      const { didDocument, signer } = issuer();
      const fetchImpl = fetchServing(didDocument);
      const cache = cacheWith(fetchImpl);

      await cache.acceptTombstone(await tombstoneFor(signer, AGENT, 1), NOW);
      await cache.acceptTombstone(await tombstoneFor(signer, OTHER_AGENT, 2), NOW);

      expect(fetchImpl).toHaveBeenCalledTimes(1);
    });

    // A signed tombstone can be captured and replayed. Hearing one proves
    // nothing about how current the view is, so it must not refresh it.
    it("does not make a stale view fresh", async () => {
      const { didDocument, signer } = issuer();
      const cache = cacheWith(fetchServing(didDocument));

      await cache.acceptTombstone(await tombstoneFor(signer), NOW);

      expect(cache.isStale(NOW)).toBe(true);
      expect(cache.status(NOW).freshAsOf).toBeNull();
    });
  });

  describe("fanning out to tool adapters", () => {
    it("notifies adapters the first time an agent is revoked", async () => {
      const { didDocument, signer } = issuer();
      const onRevoked = vi.fn(async () => {});
      const cache = cacheWith(fetchServing(didDocument), { onRevoked });

      await cache.acceptTombstone(await tombstoneFor(signer), NOW);

      expect(onRevoked).toHaveBeenCalledExactlyOnceWith(AGENT);
    });

    it("does not re-notify adapters when the same tombstone arrives again", async () => {
      const { didDocument, signer } = issuer();
      const onRevoked = vi.fn(async () => {});
      const cache = cacheWith(fetchServing(didDocument), { onRevoked });
      const tombstone = await tombstoneFor(signer);

      await cache.acceptTombstone(tombstone, NOW);
      await cache.acceptTombstone(tombstone, NOW);

      expect(onRevoked).toHaveBeenCalledTimes(1);
    });

    it("never notifies adapters for a forged tombstone", async () => {
      const { didDocument } = issuer();
      const onRevoked = vi.fn(async () => {});
      const cache = cacheWith(fetchServing(didDocument), { onRevoked });

      await cache.acceptTombstone(await tombstoneFor(issuer().signer), NOW);

      expect(onRevoked).not.toHaveBeenCalled();
    });

    it("notifies adapters about a tracked agent a resync newly shows revoked, once", async () => {
      const who = issuer();
      let revoked: number[] = [];
      const onRevoked = vi.fn(async () => {});
      const cache = cacheWith(
        fetchServing(who.didDocument, () => listFrom(who, { revoked })),
        { onRevoked },
      );
      cache.trackAgent(AGENT, entryFor(7), NOW);
      expect((await cache.resync(NOW)).ok).toBe(true);
      expect(onRevoked).not.toHaveBeenCalled();

      revoked = [7];
      await cache.resync(NOW);
      await cache.resync(NOW);

      expect(onRevoked).toHaveBeenCalledExactlyOnceWith(AGENT);
    });

    it("does not notify adapters when a push already did", async () => {
      const who = issuer();
      const onRevoked = vi.fn(async () => {});
      const cache = cacheWith(
        fetchServing(who.didDocument, () => listFrom(who, { revoked: [42] })),
        { onRevoked },
      );
      cache.trackAgent(AGENT, entryFor(42), NOW);

      await cache.acceptTombstone(await tombstoneFor(who.signer, AGENT, 42), NOW);
      await cache.resync(NOW);

      expect(onRevoked).toHaveBeenCalledTimes(1);
    });
  });

  describe("resync from the signed status list (ADR 0013)", () => {
    it("shows a tracked agent revoked when its bit is set, and others not", async () => {
      const who = issuer();
      const cache = cacheWith(fetchServing(who.didDocument, () => listFrom(who, { revoked: [5] })));
      cache.trackAgent(AGENT, entryFor(5), NOW);
      cache.trackAgent(OTHER_AGENT, entryFor(6), NOW);

      const result = await cache.resync(NOW);

      expect(result.ok && result.value).toBe(1);
      expect(cache.verdict(AGENT)).toBe("revoked");
      expect(cache.verdict(OTHER_AGENT)).toBe("ok");
    });

    it("says unknown, never ok, for an agent it was not told about", async () => {
      const { cache } = await cacheWithList([5], 5);

      expect(cache.verdict(OTHER_AGENT)).toBe("unknown");
    });

    it("treats an index past the end of the list as not revoked", async () => {
      // The list is sized to the highest revoked index, so a newer agent can sit past it.
      const { cache } = await cacheWithList([5], 9_999_999);

      expect(cache.verdict(AGENT)).toBe("ok");
    });

    it("never un-revokes: a later list that lacks the bit cannot clear it", async () => {
      const who = issuer();
      let revoked = [5];
      const cache = cacheWith(fetchServing(who.didDocument, () => listFrom(who, { revoked })));
      cache.trackAgent(AGENT, entryFor(5), NOW);
      await cache.resync(NOW);
      expect(cache.verdict(AGENT)).toBe("revoked");

      revoked = [];
      expect((await cache.resync(at(1_000))).ok).toBe(true);

      expect(cache.verdict(AGENT)).toBe("revoked");
    });

    // The agent below is not tracked when the revoking list arrives, so nothing
    // but the retained bit can show it revoked later. Replacing the stored
    // bits with each new list, instead of adding to them, fails this.
    it("keeps a bit from an earlier list for an agent that asks for a token only afterwards", async () => {
      const who = issuer();
      let revoked = [5];
      const cache = cacheWith(fetchServing(who.didDocument, () => listFrom(who, { revoked })));
      await cache.resync(NOW);

      revoked = [];
      expect((await cache.resync(at(1_000))).ok).toBe(true);
      cache.trackAgent(AGENT, entryFor(5), at(1_000));

      expect(cache.verdict(AGENT)).toBe("revoked");
    });

    it("applies a longer list after a shorter one", async () => {
      const who = issuer();
      let entries = 131_072;
      let revoked: number[] = [3];
      const cache = cacheWith(
        fetchServing(who.didDocument, () => listFrom(who, { revoked, entries })),
      );
      cache.trackAgent(AGENT, entryFor(3), NOW);
      cache.trackAgent(OTHER_AGENT, entryFor(200_000), NOW);
      await cache.resync(NOW);
      expect(cache.verdict(OTHER_AGENT)).toBe("ok");

      entries = 300_000;
      revoked = [3, 200_000];
      await cache.resync(at(1_000));

      expect(cache.verdict(OTHER_AGENT)).toBe("revoked");
    });

    it("counts an empty list as a successful sync", async () => {
      const who = issuer();
      const cache = cacheWith(fetchServing(who.didDocument, () => listFrom(who)));

      const result = await cache.resync(NOW);

      expect(result.ok && result.value).toBe(0);
      expect(cache.isStale(NOW)).toBe(false);
    });

    describe("what it refuses", () => {
      async function refused(build: (who: Issuer) => Promise<SignedCredential>) {
        const who = issuer();
        const cache = cacheWith(fetchServing(who.didDocument, () => build(who)));
        cache.trackAgent(AGENT, entryFor(5), NOW);
        const result = await cache.resync(NOW);
        expect(result.ok).toBe(false);
        // A refused list changes nothing: not fresh, nobody revoked.
        expect(cache.isStale(NOW)).toBe(true);
        expect(cache.verdict(AGENT)).toBe("ok");
        return result.ok ? null : result.error;
      }

      it("a list signed by a key that is not the revocation service's", async () => {
        const error = await refused(() => listFrom(issuer(), { revoked: [5] }));
        expect(error?.code).toBe("INVALID_STATUS_LIST");
      });

      it("a list altered after it was signed", async () => {
        const error = await refused(async (who) => {
          const good = await listFrom(who);
          const forged = createStatusList();
          forged[0] = 0xff;
          const subject = good.credentialSubject as Record<string, unknown>;
          return {
            ...good,
            credentialSubject: {
              ...subject,
              encodedList: buildStatusListSubject({ id: "x", list: forged }).encodedList,
            },
          };
        });
        expect(error?.code).toBe("INVALID_STATUS_LIST");
      });

      it("a list issued by another DID, even with a valid signature", async () => {
        const error = await refused((who) =>
          listFrom(who, { issuerDid: "did:web:127.0.0.1%3A4999" }),
        );
        expect(error?.code).toBe("INVALID_STATUS_LIST");
      });

      it("a list that is not the one published at the issuer's address", async () => {
        const error = await refused((who) => listFrom(who, { id: "http://127.0.0.1:4503/other" }));
        expect(error?.code).toBe("INVALID_STATUS_LIST");
      });

      it("a list that is not a revocation list", async () => {
        const error = await refused((who) => listFrom(who, { purpose: "suspension" }));
        expect(error?.code).toBe("INVALID_STATUS_LIST");
      });

      it("a credential that is not a status list credential", async () => {
        const error = await refused((who) => listFrom(who, { type: ["VerifiableCredential"] }));
        expect(error?.code).toBe("INVALID_STATUS_LIST");
      });

      it("a malformed payload rather than treating it as empty", async () => {
        const who = issuer();
        const cache = cacheWith(async (url: string | URL) =>
          String(url) === ISSUER_DID_URL
            ? Response.json(who.didDocument)
            : Response.json("not a credential"),
        );

        const result = await cache.resync(NOW);

        expect(result.ok).toBe(false);
        expect(cache.isStale(NOW)).toBe(true);
      });

      it("an error response from the revocation service", async () => {
        const who = issuer();
        const cache = cacheWith(async (url: string | URL) =>
          String(url) === ISSUER_DID_URL
            ? Response.json(who.didDocument)
            : new Response(null, { status: 500 }),
        );

        const result = await cache.resync(NOW);

        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.error.reason).toContain("HTTP 500");
        expect(cache.isStale(NOW)).toBe(true);
      });

      it("an unreachable revocation service", async () => {
        const cache = cacheWith(async () => {
          throw new Error("ECONNREFUSED");
        });

        expect((await cache.resync(NOW)).ok).toBe(false);
        expect(cache.isStale(NOW)).toBe(true);
      });

      it("when the issuer's key cannot be resolved", async () => {
        const who = issuer();
        const cache = cacheWith(async (url: string | URL) =>
          String(url) === ISSUER_DID_URL
            ? new Response(null, { status: 503 })
            : Response.json(await listFrom(who)),
        );

        const result = await cache.resync(NOW);

        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.error.code).toBe("UNVERIFIABLE_ISSUER");
      });
    });
  });

  // Freshness is the list's own signed time, so a replayed old list buys only
  // what is left of its window, and the two services' clocks must agree.
  describe("bounded staleness", () => {
    it("starts stale, before any sync has succeeded", () => {
      const cache = cacheWith(fetchServing(issuer().didDocument));

      expect(cache.isStale(NOW)).toBe(true);
      expect(cache.status(NOW)).toEqual({ revokedCount: 0, freshAsOf: null, stale: true });
    });

    it("is fresh after a successful resync and stale once the bound elapses", async () => {
      const who = issuer();
      const cache = cacheWith(
        fetchServing(who.didDocument, () => listFrom(who)),
        {
          maxStalenessMs: 30_000,
        },
      );

      await cache.resync(NOW);

      expect(cache.isStale(NOW)).toBe(false);
      expect(cache.isStale(at(30_000))).toBe(false);
      expect(cache.isStale(at(30_001))).toBe(true);
    });

    it("takes freshness from the signed time, so a replayed 29 s old list buys only 1 s", async () => {
      const who = issuer();
      const replayed = await listFrom(who, { validFrom: at(-29_000) });
      const cache = cacheWith(
        fetchServing(who.didDocument, () => replayed),
        {
          maxStalenessMs: 30_000,
        },
      );

      expect((await cache.resync(NOW)).ok).toBe(true);

      expect(cache.status(NOW).freshAsOf).toBe(at(-29_000).toISOString());
      expect(cache.isStale(at(1_000))).toBe(false);
      expect(cache.isStale(at(1_001))).toBe(true);
    });

    it("refuses a list older than the bound and does not refresh from it", async () => {
      const who = issuer();
      const old = await listFrom(who, { validFrom: at(-31_000) });
      const cache = cacheWith(
        fetchServing(who.didDocument, () => old),
        { maxStalenessMs: 30_000 },
      );

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("STATUS_LIST_OUT_OF_BOUNDS");
        expect(result.error.reason).toContain("clocks");
      }
      expect(cache.isStale(NOW)).toBe(true);
    });

    it("never moves freshness backwards when an older list arrives after a newer one", async () => {
      const who = issuer();
      let validFrom = at(0);
      const cache = cacheWith(fetchServing(who.didDocument, () => listFrom(who, { validFrom })));
      await cache.resync(at(0));

      validFrom = at(-10_000);
      await cache.resync(at(1_000));

      expect(cache.status(at(1_000)).freshAsOf).toBe(NOW.toISOString());
    });

    // A healthy list is a moment old on arrival, so an old one is either clock
    // drift or a replay. Both deserve a log line even though the list is accepted.
    describe("warning about an old list", () => {
      async function resyncAged(ageMs: number) {
        const who = issuer();
        const warnings: string[] = [];
        const old = await listFrom(who, { validFrom: at(-ageMs) });
        const cache = createRevocationCache({
          issuerDid: ISSUER_DID,
          revocationUrl: REVOCATION_URL,
          maxStalenessMs: 30_000,
          maxClockSkewMs: 5_000,
          onWarning: (message) => warnings.push(message),
          fetchImpl: fetchServing(who.didDocument, () => old) as unknown as typeof fetch,
        });
        const result = await cache.resync(NOW);
        return { result, warnings };
      }

      it("warns when an accepted list is older than the skew, and mentions clocks", async () => {
        const { result, warnings } = await resyncAged(20_000);

        expect(result.ok).toBe(true);
        expect(warnings).toHaveLength(1);
        expect(warnings[0]).toContain("clock");
        expect(warnings[0]).toContain("20 s");
      });

      it("stays quiet for a list that is within the skew", async () => {
        const { result, warnings } = await resyncAged(2_000);

        expect(result.ok).toBe(true);
        expect(warnings).toEqual([]);
      });

      it("does not warn about a list it refuses for age (the refusal says it)", async () => {
        const { result, warnings } = await resyncAged(60_000);

        expect(result.ok).toBe(false);
        expect(warnings).toEqual([]);
      });
    });

    it("refuses a list dated in the future beyond the allowed skew", async () => {
      const who = issuer();
      const future = await listFrom(who, { validFrom: at(6_000) });
      const cache = cacheWith(
        fetchServing(who.didDocument, () => future),
        {
          maxClockSkewMs: 5_000,
        },
      );

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.reason).toContain("ahead");
      expect(cache.isStale(NOW)).toBe(true);
    });

    it("accepts a list dated slightly ahead and counts it as fresh only up to now", async () => {
      const who = issuer();
      const ahead = await listFrom(who, { validFrom: at(3_000) });
      const cache = cacheWith(
        fetchServing(who.didDocument, () => ahead),
        {
          maxStalenessMs: 30_000,
          maxClockSkewMs: 5_000,
        },
      );

      expect((await cache.resync(NOW)).ok).toBe(true);

      expect(cache.status(NOW).freshAsOf).toBe(NOW.toISOString());
    });

    it("lets a list from a clock a little behind stay fresh, but not one behind by bound plus skew", async () => {
      const who = issuer();
      const options = { maxStalenessMs: 30_000, maxClockSkewMs: 5_000 };
      const slightlyBehind = await listFrom(who, { validFrom: at(-34_000) });
      const tooFar = await listFrom(who, { validFrom: at(-35_001) });

      const accepted = cacheWith(
        fetchServing(who.didDocument, () => slightlyBehind),
        options,
      );
      const refused = cacheWith(
        fetchServing(who.didDocument, () => tooFar),
        options,
      );

      expect((await accepted.resync(NOW)).ok).toBe(true);
      expect(accepted.isStale(NOW)).toBe(false);
      expect((await refused.resync(NOW)).ok).toBe(false);
    });
  });

  describe("tracking which bit is an agent's", () => {
    const cache = () => cacheWith(fetchServing(issuer().didDocument));

    it("accepts an entry for the trusted list", () => {
      expect(cache().trackAgent(AGENT, entryFor(12), NOW).ok).toBe(true);
    });

    it.each([
      ["missing", undefined],
      ["not an object", "5"],
      ["the wrong type", entryFor(1, { type: "SomethingElse" })],
      ["a suspension entry", entryFor(1, { statusPurpose: "suspension" })],
      [
        "a list this vault does not trust",
        entryFor(1, { statusListCredential: "http://evil.test/list" }),
      ],
      ["a numeric index instead of a string", entryFor(1, { statusListIndex: 1 })],
      ["a negative index", entryFor("-1")],
      ["a fractional index", entryFor("1.5")],
      ["a non-numeric index", entryFor("abc")],
      ["a padded index", entryFor("01")],
      ["an empty index", entryFor("")],
      ["an absurdly large index", entryFor("9".repeat(30))],
      ["an index too large to hold exactly", entryFor("9007199254740993")],
    ])("refuses %s", (_name, entry) => {
      const c = cache();

      const result = c.trackAgent(AGENT, entry, NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("INVALID_CREDENTIAL_STATUS");
      expect(c.verdict(AGENT)).toBe("unknown");
    });

    it("derives the trusted list address from the issuer DID alone", () => {
      expect(statusListUrlFor(ISSUER_DID)).toBe(LIST_URL);
      expect(statusListUrlFor("did:web:revocation.example.com")).toBe(
        "https://revocation.example.com/status/revocation",
      );
    });

    it("forgets an agent that has not asked for a token within the retention window", async () => {
      const { cache: c } = await cacheWithList([], 5);
      expect(c.verdict(AGENT)).toBe("ok");

      // Another agent asking later prunes the first once it is past retention.
      c.trackAgent(OTHER_AGENT, entryFor(6), at(TRACKED_AGENT_RETENTION_MS + 1));

      expect(c.verdict(AGENT)).toBe("unknown");
      expect(c.verdict(OTHER_AGENT)).toBe("ok");
    });

    it("keeps an agent that keeps asking", async () => {
      const { cache: c } = await cacheWithList([], 5);

      c.trackAgent(AGENT, entryFor(5), at(TRACKED_AGENT_RETENTION_MS - 1_000));
      c.trackAgent(OTHER_AGENT, entryFor(6), at(TRACKED_AGENT_RETENTION_MS + 1_000));

      expect(c.verdict(AGENT)).toBe("ok");
    });

    it("sees a revocation that arrived while the agent was pruned once it asks again", async () => {
      const who = issuer();
      const cache = cacheWith(
        fetchServing(who.didDocument, () =>
          listFrom(who, { revoked: [5], validFrom: at(TRACKED_AGENT_RETENTION_MS + 1) }),
        ),
      );
      cache.trackAgent(AGENT, entryFor(5), NOW);
      // The agent goes quiet and is pruned before the list that revokes it arrives.
      cache.trackAgent(OTHER_AGENT, entryFor(6), at(TRACKED_AGENT_RETENTION_MS + 1));
      await cache.resync(at(TRACKED_AGENT_RETENTION_MS + 1));
      expect(cache.verdict(AGENT)).toBe("unknown");

      cache.trackAgent(AGENT, entryFor(5), at(TRACKED_AGENT_RETENTION_MS + 2));

      expect(cache.verdict(AGENT)).toBe("revoked");
    });

    it("keeps an agent revoked after it is pruned", async () => {
      const { cache: c } = await cacheWithList([5], 5);
      expect(c.verdict(AGENT)).toBe("revoked");

      c.trackAgent(OTHER_AGENT, entryFor(6), at(TRACKED_AGENT_RETENTION_MS + 1));

      expect(c.verdict(AGENT)).toBe("revoked");
    });
  });

  // The revocation service's signing key changes when its seed does (ADR 0012).
  // The vault must follow the key it publishes at its did:web URL, not the
  // first one it ever saw, or every revocation after the change is dropped.
  describe("issuer key rotation", () => {
    /** Serves whichever DID document and list are current. */
    function rotatingIssuer() {
      const state = {
        didDocument: issuer().didDocument,
        list: undefined as undefined | (() => Promise<SignedCredential>),
        didFetches: 0,
      };
      const fetchImpl = vi.fn(async (url: string | URL) => {
        const href = String(url);
        if (href === ISSUER_DID_URL) {
          state.didFetches += 1;
          return Response.json(state.didDocument);
        }
        if (href === `${REVOCATION_URL}/status/revocation` && state.list) {
          return Response.json(await state.list());
        }
        return new Response(null, { status: 404 });
      });
      return { state, fetchImpl };
    }

    it("applies a list signed by the issuer's new key after it rotates", async () => {
      const before = issuer();
      const { state, fetchImpl } = rotatingIssuer();
      state.didDocument = before.didDocument;
      state.list = () => listFrom(before, { revoked: [1] });
      const cache = cacheWith(fetchImpl);
      cache.trackAgent(OTHER_AGENT, entryFor(2), NOW);
      expect((await cache.resync(NOW)).ok).toBe(true);

      const after = issuer();
      state.didDocument = after.didDocument;
      state.list = () => listFrom(after, { revoked: [1, 2], validFrom: at(10_000) });
      const result = await cache.resync(at(10_000));

      expect(result.ok).toBe(true);
      expect(cache.verdict(OTHER_AGENT)).toBe("revoked");
      expect(cache.isStale(at(10_000))).toBe(false);
    });

    it("accepts a pushed tombstone signed by the issuer's new key after it rotates", async () => {
      const before = issuer();
      const { state, fetchImpl } = rotatingIssuer();
      state.didDocument = before.didDocument;
      const cache = cacheWith(fetchImpl);
      expect(
        (await cache.acceptTombstone(await tombstoneFor(before.signer, AGENT, 1), NOW)).ok,
      ).toBe(true);

      const after = issuer();
      state.didDocument = after.didDocument;
      const result = await cache.acceptTombstone(
        await tombstoneFor(after.signer, OTHER_AGENT, 2),
        at(10_000),
      );

      expect(result.ok).toBe(true);
      expect(cache.verdict(OTHER_AGENT)).toBe("revoked");
    });

    it("still rejects a forged tombstone after re-resolving the issuer key", async () => {
      const { state, fetchImpl } = rotatingIssuer();
      state.didDocument = issuer().didDocument;
      const cache = cacheWith(fetchImpl);

      const result = await cache.acceptTombstone(await tombstoneFor(issuer().signer), NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("INVALID_TOMBSTONE");
      expect(cache.verdict(AGENT)).toBe("unknown");
    });

    it("still rejects a forged list after re-resolving the issuer key", async () => {
      const { state, fetchImpl } = rotatingIssuer();
      state.didDocument = issuer().didDocument;
      state.list = () => listFrom(issuer(), { revoked: [5] });
      const cache = cacheWith(fetchImpl);
      cache.trackAgent(AGENT, entryFor(5), NOW);

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(false);
      expect(cache.verdict(AGENT)).toBe("ok");
      expect(cache.isStale(NOW)).toBe(true);
    });

    // The push endpoint is unauthenticated, so a flood of forged tombstones
    // must not turn into a flood of DID resolutions against the issuer. The
    // list path shares the limit; a forged-tombstone flood can therefore delay
    // a legitimate list until the next interval, which fails closed.
    it("re-resolves the issuer key at most once per interval, however many forgeries arrive", async () => {
      const { state, fetchImpl } = rotatingIssuer();
      state.didDocument = issuer().didDocument;
      state.list = () => listFrom(issuer());
      const cache = cacheWith(fetchImpl);
      const forged = await tombstoneFor(issuer().signer);

      for (let i = 0; i < 20; i += 1) {
        await cache.acceptTombstone(forged, at(i * 100));
        await cache.resync(at(i * 100));
      }

      // One initial resolution plus at most one refresh within the 5 s window.
      expect(state.didFetches).toBeLessThanOrEqual(2);
    });
  });
});

import {
  buildDidWebDocument,
  generateKeyPair,
  issueRevocationTombstone,
  sign,
  type DidWebDocument,
} from "@custos/core";
import { describe, expect, it, vi } from "vitest";
import { createRevocationCache } from "./cache.js";

const ISSUER_DID = "did:web:127.0.0.1%3A4503";
const ISSUER_DID_URL = "http://127.0.0.1:4503/.well-known/did.json";
const REVOCATION_URL = "http://127.0.0.1:4503";
const AGENT = "did:web:127.0.0.1%3A4001:agents:11111111-1111-4111-8111-111111111111";
const OTHER_AGENT = "did:web:127.0.0.1%3A4001:agents:22222222-2222-4222-8222-222222222222";
const NOW = new Date("2026-09-07T10:00:00.000Z");

function issuer() {
  const keyPair = generateKeyPair();
  const didDocument = buildDidWebDocument({
    domain: "127.0.0.1:4503",
    publicKey: keyPair.publicKey,
  });
  return {
    didDocument,
    signer: { sign: async (data: Uint8Array) => sign(data, keyPair.secretKey) },
  };
}

async function tombstoneFor(
  signer: { sign: (data: Uint8Array) => Promise<Uint8Array> },
  agentDid = AGENT,
  statusListIndex = 42,
): Promise<string> {
  const issued = await issueRevocationTombstone({
    tombstone: { agentDid, statusListIndex, revokedAt: NOW.toISOString() },
    signer,
  });
  if (!issued.ok) throw new Error("expected tombstone issuance to succeed");
  return issued.value;
}

/** Serves the issuer's DID document and, optionally, a resync payload. */
function fetchServing(didDocument: DidWebDocument, tombstones: readonly string[] = []) {
  return vi.fn(async (url: string | URL) => {
    const href = String(url);
    if (href === ISSUER_DID_URL) return Response.json(didDocument);
    if (href === `${REVOCATION_URL}/revocations`) {
      return Response.json({ tombstones, asOf: NOW.toISOString() });
    }
    return new Response(null, { status: 404 });
  });
}

function cacheWith(
  fetchImpl: unknown,
  overrides: {
    readonly maxStalenessMs?: number;
    readonly onRevoked?: (did: string) => Promise<void>;
  } = {},
) {
  return createRevocationCache({
    issuerDid: ISSUER_DID,
    revocationUrl: REVOCATION_URL,
    maxStalenessMs: overrides.maxStalenessMs ?? 30_000,
    fetchImpl: fetchImpl as typeof fetch,
    ...(overrides.onRevoked ? { onRevoked: overrides.onRevoked } : {}),
  });
}

describe("revocation cache", () => {
  describe("accepting a pushed tombstone", () => {
    it("marks the agent revoked once the tombstone verifies", async () => {
      const { didDocument, signer } = issuer();
      const cache = cacheWith(fetchServing(didDocument));

      expect(cache.isRevoked(AGENT)).toBe(false);
      const accepted = await cache.acceptTombstone(await tombstoneFor(signer), NOW);

      expect(accepted.ok).toBe(true);
      expect(cache.isRevoked(AGENT)).toBe(true);
      expect(cache.isRevoked(OTHER_AGENT)).toBe(false);
    });

    // Without this check the push endpoint would let anyone who can reach
    // the vault revoke any agent.
    it("rejects a tombstone signed by a key that is not the revocation service's", async () => {
      const { didDocument } = issuer();
      const impostor = issuer();
      const cache = cacheWith(fetchServing(didDocument));

      const result = await cache.acceptTombstone(await tombstoneFor(impostor.signer), NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("INVALID_TOMBSTONE");
      expect(cache.isRevoked(AGENT)).toBe(false);
    });

    it("rejects a structurally malformed tombstone", async () => {
      const { didDocument } = issuer();
      const cache = cacheWith(fetchServing(didDocument));

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
      expect(cache.isRevoked(AGENT)).toBe(false);
    });

    it("fails closed when the issuer is unreachable", async () => {
      const { signer } = issuer();
      const cache = cacheWith(async () => {
        throw new Error("ECONNREFUSED");
      });

      const result = await cache.acceptTombstone(await tombstoneFor(signer), NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.reason).toContain("ECONNREFUSED");
    });

    it("fails closed when the issuer's document has no usable verification method", async () => {
      const { signer } = issuer();
      const cache = cacheWith(async () =>
        Response.json({ id: ISSUER_DID, verificationMethod: [] }),
      );

      const result = await cache.acceptTombstone(await tombstoneFor(signer), NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("UNVERIFIABLE_ISSUER");
    });

    it("resolves the issuer key once and reuses it", async () => {
      const { didDocument, signer } = issuer();
      const fetchImpl = fetchServing(didDocument);
      const cache = cacheWith(fetchImpl);

      await cache.acceptTombstone(await tombstoneFor(signer, AGENT), NOW);
      await cache.acceptTombstone(await tombstoneFor(signer, OTHER_AGENT), NOW);

      const didLookups = fetchImpl.mock.calls.filter(
        (call) => String(call[0]) === ISSUER_DID_URL,
      ).length;
      expect(didLookups).toBe(1);
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

    // A re-broadcast is normal (an operator forcing redelivery); it must not
    // re-hit every connector each time.
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
      const impostor = issuer();
      const onRevoked = vi.fn(async () => {});
      const cache = cacheWith(fetchServing(didDocument), { onRevoked });

      await cache.acceptTombstone(await tombstoneFor(impostor.signer), NOW);

      expect(onRevoked).not.toHaveBeenCalled();
    });
  });

  describe("bounded staleness", () => {
    // A vault that has never heard from the control plane knows nothing, and
    // must not answer "not revoked" on that basis.
    it("starts stale, before any sync has succeeded", () => {
      const cache = cacheWith(async () => new Response(null, { status: 404 }));
      expect(cache.isStale(NOW)).toBe(true);
      expect(cache.status(NOW).stale).toBe(true);
      expect(cache.status(NOW).freshAsOf).toBeNull();
    });

    it("is fresh immediately after a successful resync", async () => {
      const { didDocument } = issuer();
      const cache = cacheWith(fetchServing(didDocument));

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(true);
      expect(cache.isStale(NOW)).toBe(false);
      expect(cache.status(NOW).freshAsOf).toBe(NOW.toISOString());
    });

    it("goes stale again once the configured bound elapses", async () => {
      const { didDocument } = issuer();
      const cache = cacheWith(fetchServing(didDocument), { maxStalenessMs: 30_000 });
      await cache.resync(NOW);

      const withinBound = new Date(NOW.getTime() + 29_000);
      const pastBound = new Date(NOW.getTime() + 31_000);

      expect(cache.isStale(withinBound)).toBe(false);
      expect(cache.isStale(pastBound)).toBe(true);
    });

    it("counts an empty revocation list as a successful sync", async () => {
      const { didDocument } = issuer();
      const cache = cacheWith(fetchServing(didDocument, []));

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(true);
      if (result.ok) expect(result.value).toBe(0);
      expect(cache.isStale(NOW)).toBe(false);
    });
  });

  describe("resync", () => {
    it("applies every revocation the control plane reports", async () => {
      const { didDocument, signer } = issuer();
      const tombstones = [
        await tombstoneFor(signer, AGENT, 1),
        await tombstoneFor(signer, OTHER_AGENT, 2),
      ];
      const cache = cacheWith(fetchServing(didDocument, tombstones));

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(true);
      if (result.ok) expect(result.value).toBe(2);
      expect(cache.isRevoked(AGENT)).toBe(true);
      expect(cache.isRevoked(OTHER_AGENT)).toBe(true);
      expect(cache.status(NOW).revokedCount).toBe(2);
    });

    it("stays stale when the control plane answers with an error", async () => {
      const cache = cacheWith(async (url: string | URL) =>
        String(url) === ISSUER_DID_URL
          ? Response.json(issuer().didDocument)
          : new Response(null, { status: 500 }),
      );

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.reason).toContain("HTTP 500");
      expect(cache.isStale(NOW)).toBe(true);
    });

    it("stays stale when the control plane is unreachable", async () => {
      const cache = cacheWith(async () => {
        throw new Error("ECONNREFUSED");
      });

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(false);
      expect(cache.isStale(NOW)).toBe(true);
    });

    it("rejects a malformed resync payload rather than treating it as empty", async () => {
      const { didDocument } = issuer();
      const cache = cacheWith(async (url: string | URL) =>
        String(url) === ISSUER_DID_URL
          ? Response.json(didDocument)
          : Response.json({ tombstones: "not-an-array" }),
      );

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.reason).toContain("malformed");
      expect(cache.isStale(NOW)).toBe(true);
    });

    it("aborts the resync if the issuer key cannot be resolved", async () => {
      const { signer } = issuer();
      const tombstones = [await tombstoneFor(signer)];
      const cache = cacheWith(async (url: string | URL) =>
        String(url) === ISSUER_DID_URL
          ? new Response(null, { status: 503 })
          : Response.json({ tombstones, asOf: NOW.toISOString() }),
      );

      const result = await cache.resync(NOW);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("UNVERIFIABLE_ISSUER");
      expect(cache.isStale(NOW)).toBe(true);
    });
  });
});

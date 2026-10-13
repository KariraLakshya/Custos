import { describe, expect, it } from "vitest";
import { generateKeyPair, sign, verifyRevocationTombstone } from "@custos/core";
import type { RevocationDb } from "./db/client.js";
import { createTombstoneMemo, listTombstones } from "./revoke.js";

const DID = (n: number): string =>
  `did:web:localhost%3A4001:agents:00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

interface FakeRow {
  agentDid: string;
  statusListIndex: number;
  revokedAt: Date | null;
  reason: string | null;
}

const row = (n: number, reason: string | null = null): FakeRow => ({
  agentDid: DID(n),
  statusListIndex: n,
  revokedAt: new Date(Date.UTC(2026, 9, 1, 0, 0, n)),
  reason,
});

/** A database holding exactly these revoked rows. */
function dbWith(rows: FakeRow[]): RevocationDb {
  return {
    select: () => ({ from: () => ({ where: async () => rows }) }),
  } as unknown as RevocationDb;
}

/** A real Ed25519 signer that counts how many signatures it makes. */
function countingSigner() {
  const keyPair = generateKeyPair();
  const state = { signed: 0 };
  return {
    state,
    publicKey: keyPair.publicKey,
    signer: {
      sign: async (data: Uint8Array) => {
        state.signed += 1;
        return sign(data, keyPair.secretKey);
      },
    },
  };
}

describe("listTombstones", () => {
  it("signs every revoked row on the first call", async () => {
    const { signer, state } = countingSigner();

    const result = await listTombstones({
      db: dbWith([row(1), row(2), row(3)]),
      signer,
      memo: createTombstoneMemo(),
    });

    expect(result.ok && result.value).toHaveLength(3);
    expect(state.signed).toBe(3);
  });

  it("signs nothing again for rows it has already signed", async () => {
    const { signer, state } = countingSigner();
    const memo = createTombstoneMemo();
    const db = dbWith([row(1), row(2), row(3)]);

    const first = await listTombstones({ db, signer, memo });
    const second = await listTombstones({ db, signer, memo });

    expect(state.signed).toBe(3);
    expect(second).toEqual(first);
  });

  it("signs only the new row when one more is revoked", async () => {
    const { signer, state } = countingSigner();
    const memo = createTombstoneMemo();
    const rows = [row(1), row(2)];
    await listTombstones({ db: dbWith(rows), signer, memo });

    rows.push(row(3));
    const result = await listTombstones({ db: dbWith(rows), signer, memo });

    expect(state.signed).toBe(3);
    expect(result.ok && result.value).toHaveLength(3);
  });

  it("serves tombstones that still verify against the signing key", async () => {
    const { signer, publicKey } = countingSigner();
    const memo = createTombstoneMemo();
    const db = dbWith([row(1, "compromised"), row(2)]);

    await listTombstones({ db, signer, memo });
    const cached = await listTombstones({ db, signer, memo });

    if (!cached.ok) throw new Error("expected tombstones");
    const claims = cached.value.map((tombstone) => {
      const verified = verifyRevocationTombstone({ tombstone, publicKey });
      if (!verified.ok)
        throw new Error(`cached tombstone failed to verify: ${verified.error.code}`);
      return verified.value;
    });
    expect(claims.map((c) => c.agentDid)).toEqual([DID(1), DID(2)]);
    expect(claims[0]?.reason).toBe("compromised");
  });

  // The key is the exact signed claims. A row whose contents differ in any
  // field gets a fresh signature, never another row's cached one.
  it.each([
    ["the reason", { ...row(1), reason: "other" }],
    ["the revocation time", { ...row(1), revokedAt: new Date(Date.UTC(2026, 9, 2)) }],
    ["the status index", { ...row(1), statusListIndex: 99 }],
    ["the agent", { ...row(1), agentDid: DID(77) }],
  ])("signs again when %s differs", async (_name, changed) => {
    const { signer, state } = countingSigner();
    const memo = createTombstoneMemo();
    const original = await listTombstones({ db: dbWith([row(1)]), signer, memo });

    const result = await listTombstones({ db: dbWith([changed]), signer, memo });

    expect(state.signed).toBe(2);
    expect(result.ok && original.ok && result.value[0]).not.toBe(original.ok && original.value[0]);
  });

  it("does not cache a failure: the next call signs again", async () => {
    let fail = true;
    const keyPair = generateKeyPair();
    const signer = {
      sign: async (data: Uint8Array) => {
        if (fail) throw new Error("kms unavailable");
        return sign(data, keyPair.secretKey);
      },
    };
    const memo = createTombstoneMemo();
    const db = dbWith([row(1)]);

    const failed = await listTombstones({ db, signer, memo });
    fail = false;
    const recovered = await listTombstones({ db, signer, memo });

    expect(failed.ok).toBe(false);
    expect(recovered.ok && recovered.value).toHaveLength(1);
  });
});

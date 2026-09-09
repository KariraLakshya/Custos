import { describe, expect, it } from "vitest";
import { allocateStatusListIndex } from "./allocate.js";
import type { RevocationDb } from "../db/client.js";

const AGENT = { agentId: "0f8f6a1e-9c2b-4a3d-8f1e-1b2c3d4e5f60", agentDid: "did:web:example:a" };

/** Minimal stand-in exercising the failure paths a live database hides. */
function dbThatFailsInsert(error: unknown): RevocationDb {
  return {
    insert: () => ({
      values: () => ({
        onConflictDoNothing: () => ({
          returning: async () => {
            throw error;
          },
        }),
      }),
    }),
  } as unknown as RevocationDb;
}

/** Insert reports a conflict, but the follow-up lookup finds nothing. */
function dbWithLostRow(): RevocationDb {
  return {
    insert: () => ({
      values: () => ({
        onConflictDoNothing: () => ({ returning: async () => [] }),
      }),
    }),
    select: () => ({
      from: () => ({
        where: () => ({ limit: async () => [] }),
      }),
    }),
  } as unknown as RevocationDb;
}

describe("allocateStatusListIndex", () => {
  it("fails closed when the database is unreachable", async () => {
    const result = await allocateStatusListIndex({
      db: dbThatFailsInsert(new Error("connection refused")),
      ...AGENT,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("ALLOCATION_FAILED");
      expect(result.error.reason).toContain("connection refused");
    }
  });

  it("reports a non-Error database failure without crashing", async () => {
    const result = await allocateStatusListIndex({
      db: dbThatFailsInsert("pool drained"),
      ...AGENT,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.reason).toBe("pool drained");
  });

  // Never invent an index: issuing a credential against one we did not
  // actually reserve would point at some other agent's bit.
  it("fails rather than guess when the conflicting row cannot be read back", async () => {
    const result = await allocateStatusListIndex({ db: dbWithLostRow(), ...AGENT });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.reason).toContain("neither inserted nor found");
    }
  });
});

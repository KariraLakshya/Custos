import { randomUUID } from "node:crypto";
import { createLocalSecretCipher } from "@custos/core";
import { afterAll, describe, expect, it } from "vitest";
import { createDb } from "../db/client.js";
import { loadToolCredential, storeToolCredential, toolCredentialExists } from "./store.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);
const cipher = createLocalSecretCipher(new Uint8Array(32).fill(7));

afterAll(async () => {
  await db.$client.end();
});

describe("storeToolCredential / loadToolCredential", () => {
  it("round-trips a secret encrypted at rest", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db, cipher, tool, secret: "sk_test_12345" });

    expect(await toolCredentialExists(db, tool)).toBe(true);
    expect(await loadToolCredential({ db, cipher, tool })).toBe("sk_test_12345");
  });

  it("returns null for a tool with no stored credential", async () => {
    expect(await loadToolCredential({ db, cipher, tool: `test-tool-${randomUUID()}` })).toBeNull();
    expect(await toolCredentialExists(db, `test-tool-${randomUUID()}`)).toBe(false);
  });

  it("overwrites a previously stored credential for the same tool", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db, cipher, tool, secret: "first" });
    await storeToolCredential({ db, cipher, tool, secret: "second" });

    expect(await loadToolCredential({ db, cipher, tool })).toBe("second");
  });

  it("fails closed decrypting a credential stored under a different key", async () => {
    const tool = `test-tool-${randomUUID()}`;
    await storeToolCredential({ db, cipher, tool, secret: "sk_test_12345" });

    const otherCipher = createLocalSecretCipher(new Uint8Array(32).fill(9));
    await expect(loadToolCredential({ db, cipher: otherCipher, tool })).rejects.toThrow();
  });
});

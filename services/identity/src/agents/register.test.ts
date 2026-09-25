import { randomUUID } from "node:crypto";
import {
  buildDidWebDocument,
  buildRegistrationRequest,
  createLocalKeyProvider,
  ok,
} from "@custos/core";
import { afterAll, describe, expect, it } from "vitest";
import { createDb } from "../db/client.js";
import { agents } from "../db/schema.js";
import { registerAgent, type Issuer } from "./register.js";
import type { StatusAllocator } from "./status-allocator.js";

const db = createDb(process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos");

afterAll(async () => {
  await db.$client.end();
});

const DOMAIN = "register-race.custos.example";

async function testIssuer(): Promise<Issuer> {
  const keyProvider = createLocalKeyProvider({
    importedKeys: { issuer: new Uint8Array(32).fill(9) },
  });
  const document = buildDidWebDocument({
    domain: DOMAIN,
    publicKey: await keyProvider.getPublicKey("issuer"),
  });
  return {
    did: document.id,
    verificationMethodId: document.verificationMethod[0].id,
    keyProvider,
    keyId: "issuer",
  };
}

/**
 * An allocator that, while registration is between its duplicate-key check
 * and its insert, lets `interleave` write a conflicting row — deterministically
 * reproducing a concurrent registration winning the race.
 */
function allocatorThatInterleaves(interleave: () => Promise<void>): StatusAllocator {
  return {
    allocate: async () => {
      await interleave();
      return ok({
        statusListIndex: 1,
        statusListCredential: "http://127.0.0.1:4503/status/revocation",
      });
    },
  };
}

async function registerWith(
  allocator: StatusAllocator,
  agentId: string,
  body: { publicKey: string; proof: string },
) {
  return registerAgent({
    db,
    issuer: await testIssuer(),
    statusAllocator: allocator,
    domain: DOMAIN,
    agentId,
    request: body,
    now: new Date(),
    proofMaxSkewSeconds: 60,
  });
}

function conflictingRow(overrides: { id: string; publicKeyMultibase: string }) {
  return db.insert(agents).values({
    ...overrides,
    did: `did:web:${DOMAIN}:agents:${overrides.id}`,
    didDocument: {},
    credential: {},
  });
}

describe("registerAgent under concurrency", () => {
  it("reports KEY_ALREADY_REGISTERED when a concurrent registration of the same key inserts first", async () => {
    const request = await buildRegistrationRequest({
      audience: `did:web:${DOMAIN}`,
      now: new Date(),
    });

    const result = await registerWith(
      allocatorThatInterleaves(() =>
        conflictingRow({ id: randomUUID(), publicKeyMultibase: request.body.publicKey }).then(
          () => undefined,
        ),
      ),
      randomUUID(),
      request.body,
    );

    expect(result).toEqual({ ok: false, error: { code: "KEY_ALREADY_REGISTERED" } });
  });

  it("does not mislabel a different constraint failure as KEY_ALREADY_REGISTERED", async () => {
    const request = await buildRegistrationRequest({
      audience: `did:web:${DOMAIN}`,
      now: new Date(),
    });
    const agentId = randomUUID();

    // Same agent id (primary key), different public key: a unique violation,
    // but not the one that means "this key is already an agent".
    const attempt = registerWith(
      allocatorThatInterleaves(() =>
        conflictingRow({ id: agentId, publicKeyMultibase: `z-other-${randomUUID()}` }).then(
          () => undefined,
        ),
      ),
      agentId,
      request.body,
    );

    await expect(attempt).rejects.toThrow();
  });
});

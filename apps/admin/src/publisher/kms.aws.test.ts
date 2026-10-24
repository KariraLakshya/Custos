// Against real AWS KMS (ADR 0016): the revocation service and the publisher
// signing as one identity with one KMS key. Opt-in, never in CI:
// `pnpm --filter @custos/admin test:kms` with CUSTOS_TEST_KMS_KEY_ID set to an
// existing ECC_NIST_EDWARDS25519 / SIGN_VERIFY key and AWS credentials allowed
// kms:GetPublicKey and kms:Sign on it. Creates no keys; costs a few requests.
// Real Postgres (the hermetic DB).
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  multibaseToPublicKey,
  verifyCredential,
  verifyForeignStatusList,
  verifyRevocationTombstone,
  type DidWebDocument,
  type KeyProvider,
  type SignedCredential,
} from "@custos/core";
import { createKmsClient, createKmsKeyProvider } from "@custos/kms";
import { buildServer, createDb } from "@custos/revocation";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { publisherKeyFromEnv } from "./config.js";
import { publishOnce } from "./publish.js";
import { revokeFromPublisher } from "./revoke.js";
import { INIT, makeKit, type Kit } from "./testkit.js";

const keyId = process.env.CUSTOS_TEST_KMS_KEY_ID;

// Run deliberately (`test:kms` sets --mode kms), a missing key id is a
// failure, not a silent skip that reads as "KMS works".
if (process.env.MODE === "kms" && !keyId) {
  describe("revocation and publisher on real AWS KMS", () => {
    it("needs CUSTOS_TEST_KMS_KEY_ID set to an Ed25519 KMS key id or ARN", () => {
      expect.fail("CUSTOS_TEST_KMS_KEY_ID is not set");
    });
  });
}

const DOMAIN = "127.0.0.1:4578";

describe.skipIf(!keyId)("revocation and publisher on real AWS KMS", () => {
  const id = keyId as string;
  const db = createDb(process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos");
  const controlPlane = createTestControlPlane(db);
  const kits: Kit[] = [];
  const signedLengths: number[] = [];
  let serviceKey: string;
  let operatorKey: string;

  // The revocation service's KMS branch, recording how much it asks KMS to sign:
  // KMS signs at most 4096 raw bytes.
  const inner = createKmsKeyProvider(createKmsClient());
  const keyProvider: KeyProvider = {
    ...inner,
    sign: (keyIdToUse, data) => {
      signedLengths.push(data.length);
      return inner.sign(keyIdToUse, data);
    },
  };

  beforeAll(async () => {
    serviceKey = await controlPlane.key("service", ["status:allocate"]);
    operatorKey = await controlPlane.key("operator", ["agents:revoke"]);
  });
  afterEach(async () => {
    await Promise.all(kits.splice(0).map((k) => k.cleanup()));
  });
  afterAll(async () => {
    await db.$client.end();
  });

  it("revokes and publishes under one KMS key that every list and notice verifies against", async () => {
    const app = await buildServer({
      db,
      signingKey: { keyProvider, keyId: id },
      auditReporter: { report: () => {} },
      controlPlaneAuth: controlPlane.guard,
      didDomain: DOMAIN,
      broadcaster: { broadcast: async () => ({ delivered: 0, failed: [] }) },
    });
    const didDocument = (
      await app.inject({ method: "GET", url: "/.well-known/did.json" })
    ).json() as DidWebDocument;
    const didKey = multibaseToPublicKey(didDocument.verificationMethod[0].publicKeyMultibase);
    if (!didKey.ok) throw new Error("DID document key is not readable");
    expect(didKey.value).toEqual(await inner.getPublicKey(id));

    // The service: a revocation notice and the status list, signed in KMS.
    const agentId = randomUUID();
    const allocated = await app.inject({
      method: "POST",
      url: "/agents",
      headers: bearer(serviceKey),
      payload: { agentId, agentDid: `did:web:127.0.0.1%3A4501:agents:${agentId}` },
    });
    expect(allocated.statusCode).toBe(201);
    const revoked = await app.inject({
      method: "POST",
      url: "/revocations",
      headers: bearer(operatorKey),
      payload: { agentId, reason: "kms check" },
    });
    expect(revoked.statusCode).toBe(200);
    const { tombstones } = (await app.inject({ method: "GET", url: "/revocations" })).json() as {
      tombstones: string[];
    };
    expect(tombstones.length).toBeGreaterThan(0);
    for (const tombstone of tombstones) {
      expect(verifyRevocationTombstone({ tombstone, publicKey: didKey.value }).ok).toBe(true);
    }
    const served = (
      await app.inject({ method: "GET", url: "/status/revocation" })
    ).json() as SignedCredential;
    expect((await verifyCredential({ credential: served, didDocument })).ok).toBe(true);

    // The publisher, configured the production way, with the same key.
    const publisherKey = publisherKeyFromEnv({
      CUSTOS_PUBLISHER_KEY_PROVIDER: "kms",
      CUSTOS_PUBLISHER_KMS_KEY_ID: id,
    });
    if (!publisherKey.ok) throw new Error(publisherKey.error.reason);
    const k = await makeKit({ domain: DOMAIN });
    kits.push(k);
    const deps = { ...k.deps, ...publisherKey.value };
    expect((await publishOnce(k.config, deps, INIT)).ok).toBe(true);
    const published = await revokeFromPublisher(k.config, deps, {
      target: { index: "7", confirmIndex: "7" },
      operator: "kms-check",
      reason: "kms check",
    });
    expect(published.ok).toBe(true);

    // A foreign verifier anchored only on the service's DID document accepts it.
    const verified = await verifyForeignStatusList({
      credential: JSON.parse(await readFile(k.out, "utf8")) as unknown,
      anchor: {
        statusIssuerDid: didDocument.id,
        statusIssuerPublicKey: didKey.value,
        statusListId: (served as { id: string }).id,
        maxStatusAgeSeconds: k.config.validitySeconds,
      },
      now: k.clock.now(),
      maxClockSkewSeconds: 5,
    });
    expect(verified.ok).toBe(true);

    expect(Math.max(...signedLengths)).toBeLessThanOrEqual(4096);
    console.info(`largest message signed in KMS: ${Math.max(...signedLengths)} bytes`);
  });
});

// The publisher against A's real revocation service (ADR 0014): a list the
// publisher signs is accepted by A's own reconciler, merged into A's own state,
// served back by A, and survives A's restart. Real Postgres (the hermetic DB).
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import {
  buildDidWebDocument,
  decodeStatusList,
  isRevoked,
  multibaseToPublicKey,
  verifyForeignStatusList,
} from "@custos/core";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { buildServer, createDb } from "@custos/revocation";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { publishOnce, publisherIdentity } from "./publish.js";
import { revokeFromPublisher } from "./revoke.js";
import { INIT, SEED, keyFor, makeKit, T0, type Kit } from "./testkit.js";

const db = createDb(process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos");
const controlPlane = createTestControlPlane(db);
let serviceKey: string;
beforeAll(async () => {
  serviceKey = await controlPlane.key("service", ["status:allocate"]);
});
afterAll(async () => {
  await db.$client.end();
});

const kits: Kit[] = [];
afterEach(async () => {
  await Promise.all(kits.splice(0).map((k) => k.cleanup()));
});

// The revocation service and the publisher share one identity: the same seed, the same domain.
const DOMAIN = "127.0.0.1:4577";

async function revocationService(k: Kit, now: Date, options: { federated?: boolean } = {}) {
  const app = await buildServer({
    db,
    signingKey: keyFor(SEED),
    auditReporter: { report: () => {} },
    controlPlaneAuth: controlPlane.guard,
    didDomain: DOMAIN,
    clock: { now: () => now },
    broadcaster: { broadcast: async () => ({ delivered: 0, failed: [] }) },
    ...(options.federated === false
      ? {}
      : {
          publishedList: {
            maxAgeSeconds: k.config.validitySeconds,
            maxClockSkewSeconds: 5,
            fetchList: async () => JSON.parse(await readFile(k.out, "utf8")) as unknown,
          },
        }),
  });
  return app;
}

async function servedBits(app: Awaited<ReturnType<typeof revocationService>>) {
  const response = await app.inject({ method: "GET", url: "/status/revocation" });
  expect(response.statusCode).toBe(200);
  const decoded = decodeStatusList(
    (response.json() as { credentialSubject: { encodedList: string } }).credentialSubject
      .encodedList,
  );
  if (!decoded.ok) throw new Error("fixture");
  return decoded.value;
}

describe("a list the publisher signs, against A's real revocation service", () => {
  it("uses the identity A's service publishes: same DID, same list address, same key", async () => {
    const k = await makeKit({ domain: DOMAIN });
    kits.push(k);
    const app = await revocationService(k, T0, { federated: false });
    const didDocument = (
      await app.inject({ method: "GET", url: "/.well-known/did.json" })
    ).json() as ReturnType<typeof buildDidWebDocument>;
    const identity = await publisherIdentity(k.config, k.deps);
    expect(identity.did).toBe(didDocument.id);
    expect(identity.verificationMethodId).toBe(didDocument.verificationMethod[0].id);
    expect(identity.publicKeyMultibase).toBe(didDocument.verificationMethod[0].publicKeyMultibase);

    const served = (await app.inject({ method: "GET", url: "/status/revocation" })).json() as {
      id: string;
      issuer: string;
    };
    expect(identity.listId).toBe(served.id);
    expect(identity.did).toBe(served.issuer);
  });

  it("is accepted by a foreign verifier whose anchor is built only from A's published DID document", async () => {
    const k = await makeKit({ domain: DOMAIN });
    kits.push(k);
    const app = await revocationService(k, T0, { federated: false });
    await publishOnce(k.config, k.deps, INIT);

    const didDocument = (
      await app.inject({ method: "GET", url: "/.well-known/did.json" })
    ).json() as ReturnType<typeof buildDidWebDocument>;
    const key = multibaseToPublicKey(didDocument.verificationMethod[0].publicKeyMultibase);
    if (!key.ok) throw new Error("fixture");
    const served = (await app.inject({ method: "GET", url: "/status/revocation" })).json() as {
      id: string;
    };
    const verified = await verifyForeignStatusList({
      credential: JSON.parse(await readFile(k.out, "utf8")) as unknown,
      anchor: {
        statusIssuerDid: didDocument.id,
        statusIssuerPublicKey: key.value,
        statusListId: served.id,
        maxStatusAgeSeconds: 3600,
      },
      now: T0,
      maxClockSkewSeconds: 5,
    });
    expect(verified.ok).toBe(true);
  });

  it("is merged by A's reconciler: A revokes the agent, serves the bit, and keeps it across a restart", async () => {
    const k = await makeKit({ domain: DOMAIN });
    kits.push(k);
    const first = await revocationService(k, T0);
    const agentId = randomUUID();
    const allocated = await first.inject({
      method: "POST",
      url: "/agents",
      headers: bearer(serviceKey),
      payload: { agentId, agentDid: `did:web:identity.a.example:agents:${agentId}` },
    });
    const { statusListIndex } = allocated.json() as { statusListIndex: number };

    // The operator revokes from the publisher's machine; A's service never hears of it directly.
    await publishOnce(k.config, k.deps, INIT);
    const revoked = await revokeFromPublisher(k.config, k.deps, {
      target: { index: String(statusListIndex), confirmIndex: String(statusListIndex) },
      operator: "lakshya",
      reason: "key leaked",
    });
    expect(revoked.ok).toBe(true);

    // Until A has merged a published list it says nothing about who is revoked.
    expect((await first.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(503);
    expect(await first.publishedList!.reconcileOnce(T0)).toMatchObject({
      ok: true,
      value: { revokedAgents: 1, confirmed: true },
    });

    const row = (
      await db.$client.query<{ revoked_at: Date | null; reason: string | null }>(
        "SELECT revoked_at, reason FROM status_list_entries WHERE agent_id = $1",
        [agentId],
      )
    ).rows[0]!;
    expect(row.revoked_at).not.toBeNull();
    expect(row.reason).toBe("published-list");
    expect(isRevoked(await servedBits(first), statusListIndex)).toEqual({ ok: true, value: true });

    // A restarts: a fresh service still serves the revocation once it has merged again.
    const restarted = await revocationService(k, new Date(T0.getTime() + 60_000));
    expect((await restarted.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(
      503,
    );
    await restarted.publishedList!.reconcileOnce(new Date(T0.getTime() + 60_000));
    expect(isRevoked(await servedBits(restarted), statusListIndex)).toEqual({
      ok: true,
      value: true,
    });
  });

  it("is refused by A's reconciler if signed with a key other than A's revocation key", async () => {
    const k = await makeKit({ domain: DOMAIN });
    kits.push(k);
    const app = await revocationService(k, T0);
    const other = { ...k, deps: { ...k.deps, ...keyFor("44".repeat(32)) } };
    await publishOnce(other.config, other.deps, INIT);
    expect(await app.publishedList!.reconcileOnce(T0)).toMatchObject({
      ok: false,
      error: { code: "LIST_REJECTED" },
    });
    expect((await app.inject({ method: "GET", url: "/status/revocation" })).statusCode).toBe(503);
  });
});

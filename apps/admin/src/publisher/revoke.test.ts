import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  generateKeyPair,
  publicKeyToMultibase,
  isRevoked,
  verifyForeignStatusList,
} from "@custos/core";
import type { KmsClient } from "@custos/kms";
import { fakeKms } from "@custos/kms/testing";
import { afterEach, describe, expect, it } from "vitest";
import { publisherKeyFromEnv } from "./config.js";
import { publishOnce, publisherIdentity, publisherPaths } from "./publish.js";
import { revokeFromPublisher, type PinnedIdentity } from "./revoke.js";
import { INIT, issueAgentCredential, LIST_ID, makeKit, readList, type Kit } from "./testkit.js";

const kits: Kit[] = [];
afterEach(async () => {
  await Promise.all(kits.splice(0).map((k) => k.cleanup()));
});

const IDENTITY_DID = "did:web:identity.a.example";
const identityKeys = generateKeyPair();
const pinned: PinnedIdentity = {
  did: IDENTITY_DID,
  publicKeyMultibase: publicKeyToMultibase(identityKeys.publicKey),
};

async function started(): Promise<Kit> {
  const k = await makeKit();
  kits.push(k);
  const init = await publishOnce(k.config, k.deps, INIT);
  if (!init.ok) throw new Error(init.error.code);
  return k;
}

async function credentialFile(
  k: Kit,
  options: Partial<Parameters<typeof issueAgentCredential>[0]> = {},
  wrap = false,
) {
  const credential = await issueAgentCredential({
    identityDid: IDENTITY_DID,
    identityKeys,
    index: 321,
    ...options,
  });
  const path = join(k.dir, `agent-${crypto.randomUUID()}.json`);
  await writeFile(path, JSON.stringify(wrap ? { credential } : credential));
  return { path, credential };
}

const byCredential = (
  k: Kit,
  path: string,
  extra: { pinnedIdentity?: PinnedIdentity | null } = {},
) =>
  revokeFromPublisher(k.config, k.deps, {
    target: { credentialPath: path },
    operator: "lakshya",
    reason: "key leaked",
    ...(extra.pinnedIdentity === null ? {} : { pinnedIdentity: extra.pinnedIdentity ?? pinned }),
  });

const journalLines = async (k: Kit): Promise<string[]> =>
  (await readFile(publisherPaths(k.config).journal, "utf8")).split("\n").filter(Boolean);

describe("revoke by credential", () => {
  it("reads the index from a genuine credential, records the agent, and publishes", async () => {
    const k = await started();
    const { path, credential } = await credentialFile(k);
    const result = await byCredential(k, path);
    expect(result).toMatchObject({
      ok: true,
      value: {
        index: 321,
        agentDid: (credential.credentialSubject as { id: string }).id,
        published: { revokedCount: 1 },
      },
    });
    const identity = await publisherIdentity(k.config, k.deps);
    const view = await verifyForeignStatusList({
      credential: await readList(k.out),
      anchor: {
        statusIssuerDid: identity.did,
        statusIssuerPublicKey: identity.publicKey,
        statusListId: identity.listId,
        maxStatusAgeSeconds: 3600,
      },
      now: k.clock.now(),
      maxClockSkewSeconds: 5,
    });
    expect(view.ok && isRevoked(view.value.list, 321)).toEqual({ ok: true, value: true });
    expect(JSON.parse((await journalLines(k))[0]!)).toMatchObject({
      index: 321,
      operator: "lakshya",
      reason: "key leaked",
      agentDid: (credential.credentialSubject as { id: string }).id,
    });
  });

  it("also accepts the JSON that `register` prints, which wraps the credential", async () => {
    const k = await started();
    const { path } = await credentialFile(k, { index: 5 }, true);
    expect(await byCredential(k, path)).toMatchObject({ ok: true, value: { index: 5 } });
  });

  it("will not name an agent without A's identity pinned", async () => {
    const k = await started();
    const { path } = await credentialFile(k);
    expect(await byCredential(k, path, { pinnedIdentity: null })).toEqual({
      ok: false,
      error: { code: "IDENTITY_NOT_CONFIGURED" },
    });
    expect(await journalLines(k)).toEqual([]);
  });

  describe("refuses, and records nothing, for a file that is not a real agent of this publisher", () => {
    const refused = async (
      k: Kit,
      path: string,
      expected: string,
      pinnedIdentity?: PinnedIdentity,
    ) => {
      const result = await byCredential(
        k,
        path,
        pinnedIdentity === undefined ? {} : { pinnedIdentity },
      );
      expect(result, expected).toMatchObject({
        ok: false,
        error: { code: "INVALID_TARGET", reason: expect.stringContaining(expected) },
      });
      expect(await journalLines(k)).toEqual([]);
    };

    it("a credential signed by some other key, even one naming the pinned identity", async () => {
      const k = await started();
      const forged = await credentialFile(k, { identityKeys: generateKeyPair() });
      await refused(k, forged.path, "signature does not verify");
    });

    it("a credential from a different issuer", async () => {
      const k = await started();
      const stranger = await credentialFile(k, { identityDid: "did:web:evil.example" });
      await refused(k, stranger.path, "not issued by the pinned identity");
    });

    it("a credential edited after it was signed, so the typo or the swap cannot pass", async () => {
      const k = await started();
      const { path, credential } = await credentialFile(k, { index: 100 });
      const edited = structuredClone(credential) as unknown as {
        credentialStatus: { statusListIndex: string };
      };
      edited.credentialStatus.statusListIndex = "101";
      await writeFile(path, JSON.stringify(edited));
      await refused(k, path, "signature does not verify");
    });

    it("a credential for a different status list", async () => {
      const k = await started();
      const other = await credentialFile(k, {
        statusListCredential: "https://other.example/status/revocation",
      });
      await refused(k, other.path, "different status list");
    });

    it("a credential with no status entry", async () => {
      const k = await started();
      const bare = await credentialFile(k, { noStatus: true });
      await refused(k, bare.path, "no revocation status entry");
    });

    it("a missing file, a file that is not JSON, and a file that is too large", async () => {
      const k = await started();
      await refused(k, join(k.dir, "missing.json"), "cannot read");
      const text = join(k.dir, "text.json");
      await writeFile(text, "this is not json");
      await refused(k, text, "not JSON");
      const huge = join(k.dir, "huge.json");
      await writeFile(huge, "x".repeat(70_000));
      await refused(k, huge, "too large");
    });

    it("JSON that is not a credential, and a pinned key that is not a key", async () => {
      const k = await started();
      for (const [name, body] of [
        ["array.json", "[]"],
        ["number.json", "7"],
        ["null.json", "null"],
      ] as const) {
        const path = join(k.dir, name);
        await writeFile(path, body);
        await refused(k, path, "not a credential");
      }
      const { path } = await credentialFile(k);
      await refused(k, path, "not a valid public key", {
        did: IDENTITY_DID,
        publicKeyMultibase: "nope",
      });
    });
  });

  it("answers in the list id the publisher itself publishes", async () => {
    const k = await started();
    expect((await publisherIdentity(k.config, k.deps)).listId).toBe(LIST_ID);
  });
});

describe("revoke by index", () => {
  const byIndex = (k: Kit, index: string, confirmIndex: string, extra = {}) =>
    revokeFromPublisher(k.config, k.deps, {
      target: { index, confirmIndex },
      operator: "lakshya",
      reason: "r",
      ...extra,
    });

  it("revokes when the number is typed twice, the same", async () => {
    const k = await started();
    expect(await byIndex(k, "1234", "1234")).toMatchObject({ ok: true, value: { index: 1234 } });
  });

  it("changes nothing when the two numbers differ: revocation cannot be undone", async () => {
    const k = await started();
    const before = await readFile(k.out, "utf8");
    expect(await byIndex(k, "1234", "1243")).toMatchObject({
      ok: false,
      error: { code: "INVALID_TARGET", reason: expect.stringContaining("differ") },
    });
    expect(await journalLines(k)).toEqual([]);
    expect(await readFile(k.out, "utf8")).toBe(before);
  });

  it("refuses an index that is not a plain decimal number inside the list's range", async () => {
    const k = await started();
    for (const bad of [
      "-1",
      "1.5",
      "0x10",
      " 7",
      "",
      "1e3",
      "abc",
      "9".repeat(17),
      String(16 * 1024 * 1024 * 8),
    ]) {
      expect(await byIndex(k, bad, bad), bad).toMatchObject({
        ok: false,
        error: { code: "INVALID_TARGET" },
      });
    }
    expect(await journalLines(k)).toEqual([]);
  });

  it("requires an operator and a reason: they are what the journal records", async () => {
    const k = await started();
    for (const extra of [{ operator: "" }, { operator: "  " }, { reason: "" }, { reason: "   " }]) {
      expect(await byIndex(k, "5", "5", extra)).toMatchObject({
        ok: false,
        error: { code: "INVALID_TARGET" },
      });
    }
    expect(await journalLines(k)).toEqual([]);
  });

  it("is idempotent: revoking the same agent twice leaves one bit and two journal lines", async () => {
    const k = await started();
    await byIndex(k, "8", "8");
    expect(await byIndex(k, "8", "8")).toMatchObject({
      ok: true,
      value: { published: { revokedCount: 1 } },
    });
    expect(await journalLines(k)).toHaveLength(2); // the evidence keeps both attempts
  });

  it("surfaces a damaged journal instead of publishing", async () => {
    const k = await started();
    await writeFile(publisherPaths(k.config).journal, "garbage\n{}\n");
    expect(await byIndex(k, "8", "8")).toMatchObject({
      ok: false,
      error: { code: "JOURNAL_CORRUPT" },
    });
  });
});

// ADR 0016: revoking is the emergency path, so a KMS outage must not stop the
// revocation being recorded. `revoke` runs in a fresh process, so nothing has
// read the key yet.
describe("revoking while the KMS key cannot be reached", () => {
  const KEY_ARN = "arn:aws:kms:ap-south-1:111122223333:key/revocation";

  async function startedOnKms() {
    const kms = fakeKms();
    kms.keys.set(KEY_ARN, generateKeyPair());
    const outage = { on: false };
    const client = {
      send: (command: Parameters<KmsClient["send"]>[0]) =>
        outage.on ? Promise.reject(new Error("ThrottlingException")) : kms.client.send(command),
    } as KmsClient;
    // Each call is a new process: a provider that has read nothing yet.
    const freshKey = () => {
      const key = publisherKeyFromEnv(
        { CUSTOS_PUBLISHER_KEY_PROVIDER: "kms", CUSTOS_PUBLISHER_KMS_KEY_ID: KEY_ARN },
        { kmsClient: client },
      );
      if (!key.ok) throw new Error(key.error.reason);
      return key.value;
    };
    const k = await makeKit();
    kits.push(k);
    const init = await publishOnce(k.config, { ...k.deps, ...freshKey() }, INIT);
    if (!init.ok) throw new Error(init.error.code);
    return { k, outage, freshKey };
  }

  it("records a revocation by index in the journal, and the next publish carries it", async () => {
    const { k, outage, freshKey } = await startedOnKms();
    outage.on = true;

    const result = await revokeFromPublisher(
      k.config,
      { ...k.deps, ...freshKey() },
      {
        target: { index: "9", confirmIndex: "9" },
        operator: "lakshya",
        reason: "key leaked",
      },
    );

    expect(result).toMatchObject({
      ok: false,
      error: { code: "NOT_PUBLISHED", reason: { code: "KEY_UNAVAILABLE" } },
    });
    expect((await journalLines(k)).map((line) => JSON.parse(line) as { index: number })).toEqual([
      expect.objectContaining({ index: 9 }),
    ]);

    outage.on = false;
    const deps = { ...k.deps, ...freshKey() };
    const published = await publishOnce(k.config, deps);
    expect(published.ok).toBe(true);
    const identity = await publisherIdentity(k.config, deps);
    const view = await verifyForeignStatusList({
      credential: await readList(k.out),
      anchor: {
        statusIssuerDid: identity.did,
        statusIssuerPublicKey: identity.publicKey,
        statusListId: identity.listId,
        maxStatusAgeSeconds: k.config.validitySeconds,
      },
      now: k.clock.now(),
      maxClockSkewSeconds: 5,
    });
    if (!view.ok) throw new Error(view.error.code);
    const bit = isRevoked(view.value.list, 9);
    expect(bit.ok && bit.value).toBe(true);
  });

  it("records a revocation by credential in the journal, naming the agent", async () => {
    const { k, outage, freshKey } = await startedOnKms();
    const { path, credential } = await credentialFile(k);
    outage.on = true;

    const result = await revokeFromPublisher(
      k.config,
      { ...k.deps, ...freshKey() },
      {
        target: { credentialPath: path },
        operator: "lakshya",
        reason: "key leaked",
        pinnedIdentity: pinned,
      },
    );

    expect(result).toMatchObject({
      ok: false,
      error: { code: "NOT_PUBLISHED", reason: { code: "KEY_UNAVAILABLE" } },
    });
    expect(
      (await journalLines(k)).map(
        (line) => JSON.parse(line) as { index: number; agentDid: string },
      ),
    ).toEqual([
      expect.objectContaining({
        index: 321,
        agentDid: (credential.credentialSubject as { id: string }).id,
      }),
    ]);
  });
});

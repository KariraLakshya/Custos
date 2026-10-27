import {
  DeleteObjectCommand,
  ListObjectsV2Command,
  ListObjectVersionsCommand,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import { describe, expect, it } from "vitest";
import { createS3SealStore } from "./s3-seal-store.js";
import { openSealStore, SealCopyConflictError, SealStoreMisconfiguredError } from "./seal-store.js";
import { fakeS3, fakeS3Error } from "./testing.js";

// ADR 0017 part 2b. Against a stand-in for a versioned Object Lock bucket;
// s3-seal-store.aws.test.ts runs the same store against real S3.
const LOG = "did:web:audit.a.example";

function store(s3 = fakeS3()) {
  return { s3, seals: createS3SealStore({ client: s3.client, bucket: "seals-bucket" }) };
}

describe("createS3SealStore", () => {
  it("writes each seal once, under its log's folder, by zero-padded seq", async () => {
    const { s3, seals } = store();
    await seals.put({ log: LOG, seq: 7, seal: "seal-7" });

    const put = s3.sent.find((c) => c instanceof PutObjectCommand)!;
    expect(put.input).toMatchObject({
      Bucket: "seals-bucket",
      Key: "seals/did%3Aweb%3Aaudit.a.example/00000000000000000007.json",
      Body: "seal-7",
      IfNoneMatch: "*",
    });
  });

  it("lists copies for one log, oldest first, from a seq (inclusive), across pages", async () => {
    const { seals } = store(fakeS3({ pageSize: 2 }));
    for (const seq of [12, 1, 2, 5, 10]) await seals.put({ log: LOG, seq, seal: `seal-${seq}` });
    await seals.put({ log: "did:web:audit.b.example", seq: 3, seal: "other-log" });

    expect(await seals.list(LOG, 1)).toEqual(["seal-1", "seal-2", "seal-5", "seal-10", "seal-12"]);
    expect(await seals.list(LOG, 2)).toEqual(["seal-2", "seal-5", "seal-10", "seal-12"]);
    expect(await seals.list(LOG, 5)).toEqual(["seal-5", "seal-10", "seal-12"]);
    expect(await seals.list(LOG, 6)).toEqual(["seal-10", "seal-12"]);
    expect(await seals.list(LOG, 13)).toEqual([]);
    expect(await seals.list("did:web:audit.c.example", 1)).toEqual([]);
  });

  it("accepts the same copy again", async () => {
    const { seals } = store();
    await seals.put({ log: LOG, seq: 1, seal: "seal-1" });
    await expect(seals.put({ log: LOG, seq: 1, seal: "seal-1" })).resolves.toBeUndefined();
  });

  it("refuses a different seal at a position already stored: evidence of a rewrite", async () => {
    const { seals } = store();
    await seals.put({ log: LOG, seq: 1, seal: "seal-1" });
    await expect(seals.put({ log: LOG, seq: 1, seal: "forged" })).rejects.toBeInstanceOf(
      SealCopyConflictError,
    );
    expect(await seals.list(LOG, 1)).toEqual(["seal-1"]);
  });

  it("treats a write that raced another (409) like one already stored", async () => {
    let raced = false;
    const s3 = fakeS3({
      before: (command) => {
        if (command instanceof PutObjectCommand && !raced) {
          raced = true;
          s3.objects.set(command.input.Key!, [{ versionId: "other", body: "forged" }]);
          throw fakeS3Error("ConditionalRequestConflict", 409);
        }
      },
    });
    const { seals } = store(s3);
    await expect(seals.put({ log: LOG, seq: 1, seal: "seal-1" })).rejects.toBeInstanceOf(
      SealCopyConflictError,
    );
  });

  it("passes on any other failure to write", async () => {
    const { seals } = store(
      fakeS3({
        before: (command) => {
          if (command instanceof PutObjectCommand) throw fakeS3Error("InternalError", 500);
        },
      }),
    );
    await expect(seals.put({ log: LOG, seq: 1, seal: "seal-1" })).rejects.toThrow("InternalError");
  });

  // The attack Object Lock alone does not stop: a plain delete adds a delete
  // marker (allowed even under COMPLIANCE), which hides the locked seal from
  // ordinary listings, and If-None-Match then lets a different seal in.
  it("still returns a seal hidden behind a delete marker, beside the one put in its place", async () => {
    const { s3, seals } = store();
    await seals.put({ log: LOG, seq: 1, seal: "seal-1" });
    await seals.put({ log: LOG, seq: 2, seal: "seal-2" });
    const key = "seals/did%3Aweb%3Aaudit.a.example/00000000000000000002.json";
    await s3.client.send(new DeleteObjectCommand({ Bucket: "seals-bucket", Key: key }));
    await s3.client.send(
      new PutObjectCommand({
        Bucket: "seals-bucket",
        Key: key,
        Body: "forged-2",
        IfNoneMatch: "*",
      }),
    );

    const listed = await seals.list(LOG, 1);
    expect(listed).toContain("seal-2");
    expect(listed).toContain("forged-2");
    expect(listed).toHaveLength(3);
    // Reading the current listing instead would have missed the original.
    expect(s3.sent.some((c) => c instanceof ListObjectsV2Command)).toBe(false);
    expect(s3.sent.some((c) => c instanceof ListObjectVersionsCommand)).toBe(true);
  });

  it("still returns a seal hidden behind a delete marker with nothing put in its place", async () => {
    const { s3, seals } = store();
    await seals.put({ log: LOG, seq: 1, seal: "seal-1" });
    await s3.client.send(
      new DeleteObjectCommand({
        Bucket: "seals-bucket",
        Key: "seals/did%3Aweb%3Aaudit.a.example/00000000000000000001.json",
      }),
    );
    expect(await seals.list(LOG, 1)).toEqual(["seal-1"]);
  });

  it("refuses an object in a log's folder that is not a seal, rather than skip it", async () => {
    const { s3, seals } = store();
    await seals.put({ log: LOG, seq: 1, seal: "seal-1" });
    s3.objects.set("seals/did%3Aweb%3Aaudit.a.example/notes.txt", [{ versionId: "x", body: "hi" }]);
    await expect(seals.list(LOG, 1)).rejects.toThrow("not a seal");
  });

  it("refuses an object far larger than a seal", async () => {
    const { s3, seals } = store();
    s3.objects.set("seals/did%3Aweb%3Aaudit.a.example/00000000000000000001.json", [
      { versionId: "x", body: "a".repeat(20_000) },
    ]);
    await expect(seals.list(LOG, 1)).rejects.toThrow("not a seal");
  });
});

type Lock = NonNullable<Parameters<typeof fakeS3>[0]>["lockConfiguration"];

describe("checkWriteOnce", () => {
  const check = (lockConfiguration: Lock) =>
    store(fakeS3({ lockConfiguration })).seals.checkWriteOnce();

  it("accepts Object Lock with a default COMPLIANCE retention", async () => {
    await expect(
      check({
        ObjectLockEnabled: "Enabled",
        Rule: { DefaultRetention: { Mode: "COMPLIANCE", Years: 1 } },
      }),
    ).resolves.toBe("ok");
  });

  it.each([
    ["no Object Lock", {}],
    [
      "GOVERNANCE retention, which an admin can bypass",
      { ObjectLockEnabled: "Enabled", Rule: { DefaultRetention: { Mode: "GOVERNANCE", Days: 1 } } },
    ],
    ["no default retention", { ObjectLockEnabled: "Enabled" }],
    [
      "a zero-day retention",
      { ObjectLockEnabled: "Enabled", Rule: { DefaultRetention: { Mode: "COMPLIANCE", Days: 0 } } },
    ],
  ] as const)("refuses a bucket with %s", async (_, lock) => {
    await expect(check(lock as never)).rejects.toBeInstanceOf(SealStoreMisconfiguredError);
  });

  it.each([
    ["no lock configuration", fakeS3Error("ObjectLockConfigurationNotFoundError", 404)],
    ["no such bucket", fakeS3Error("NoSuchBucket", 404)],
    ["no permission to ask", fakeS3Error("AccessDenied", 403)],
  ])("refuses when S3 answers %s", async (_, error) => {
    await expect(check(error)).rejects.toBeInstanceOf(SealStoreMisconfiguredError);
  });

  it.each([
    ["S3 cannot be reached", new Error("ECONNREFUSED")],
    ["S3 fails on its side", fakeS3Error("ServiceUnavailable", 503)],
  ])("reports unreachable, not misconfigured, when %s", async (_, error) => {
    await expect(check(error)).resolves.toBe("unreachable");
  });
});

describe("openSealStore", () => {
  it("opens an s3:// URL after checking the bucket is write-once", async () => {
    const s3 = fakeS3();
    const seals = await openSealStore("s3://seals-bucket", { s3Client: s3.client });
    await seals.put({ log: LOG, seq: 1, seal: "seal-1" });
    expect(s3.sent[0]!.constructor.name).toBe("GetObjectLockConfigurationCommand");
    expect(s3.objects.size).toBe(1);
  });

  it("refuses to open a bucket that is not write-once", async () => {
    const s3 = fakeS3({ lockConfiguration: {} });
    await expect(
      openSealStore("s3://seals-bucket", { s3Client: s3.client }),
    ).rejects.toBeInstanceOf(SealStoreMisconfiguredError);
  });

  it("opens one S3 cannot reach yet; its first read fails instead", async () => {
    const s3 = fakeS3({
      before: () => {
        throw new Error("ECONNREFUSED");
      },
    });
    const seals = await openSealStore("s3://seals-bucket", { s3Client: s3.client });
    await expect(seals.list(LOG, 1)).rejects.toThrow("ECONNREFUSED");
  });

  it.each(["s3://", "s3://bucket/folder", "s3://bucket?x=1", "s3://user@bucket"])(
    "refuses %s: only s3://<bucket>",
    async (url) => {
      await expect(openSealStore(url, { s3Client: fakeS3().client })).rejects.toThrow();
    },
  );

  it("refuses an unknown scheme without repeating the URL, which may hold a password", async () => {
    const error = await openSealStore("mysql://admin:hunter2@db/seals").catch((e: Error) => e);
    expect((error as Error).message).toBe("unsupported seal store URL scheme: mysql");
    expect((error as Error).message).not.toContain("hunter2");
  });

  it("opens a postgres:// URL without connecting", async () => {
    const seals = await openSealStore("postgres://custos_auditor:x@127.0.0.1:1/none");
    await seals.close();
  });
});

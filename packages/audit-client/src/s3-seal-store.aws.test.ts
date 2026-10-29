import { randomUUID } from "node:crypto";
import { DeleteObjectCommand, HeadObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { describe, expect, it } from "vitest";
import { createS3SealClient, createS3SealStore } from "./s3-seal-store.js";
import { SealCopyConflictError } from "./seal-store.js";

/**
 * Against a real S3 bucket with Object Lock — what the stand-in in
 * s3-seal-store.test.ts cannot prove: that real S3 accepts the writes (Object
 * Lock needs a checksum the SDK must send), locks each one, refuses an
 * overwrite and a version delete, and that a plain delete hides nothing from
 * the store's read. Opt-in, never in CI: `pnpm --filter @custos/audit-client
 * test:s3` with CUSTOS_TEST_SEAL_BUCKET set to a bucket with Object Lock and
 * a default COMPLIANCE retention, and AWS credentials allowed what
 * infra/seal-store/aws/live-test-policy.json grants. Every object it writes
 * stays locked for the bucket's retention period; it writes about five.
 */
const bucket = process.env.CUSTOS_TEST_SEAL_BUCKET;

// Run deliberately (`test:s3` sets --mode s3), a missing bucket is a failure,
// not a silent skip that reads as "S3 works".
if (process.env.MODE === "s3" && !bucket) {
  describe("real AWS S3", () => {
    it("needs CUSTOS_TEST_SEAL_BUCKET set to an Object Lock bucket", () => {
      expect.fail("CUSTOS_TEST_SEAL_BUCKET is not set");
    });
  });
}

describe.skipIf(!bucket)("createS3SealStore against real AWS S3 Object Lock", () => {
  const client = createS3SealClient();
  const store = createS3SealStore({ client, bucket: bucket as string });
  // A fresh log per run, so runs never meet each other's locked objects.
  const log = `did:web:live-test.invalid:${randomUUID()}`;
  const keyOf = (seq: number) =>
    `seals/${encodeURIComponent(log)}/${String(seq).padStart(20, "0")}.json`;

  it("finds the bucket write-once: Object Lock with default COMPLIANCE retention", async () => {
    expect(await store.checkWriteOnce()).toBe("ok");
  });

  it("writes a seal that S3 locks in COMPLIANCE mode, and lists it", async () => {
    await store.put({ log, seq: 1, seal: "seal-1" });
    const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: keyOf(1) }));
    expect(head.ObjectLockMode).toBe("COMPLIANCE");
    expect(head.ObjectLockRetainUntilDate!.getTime()).toBeGreaterThan(Date.now());
    expect(await store.list(log, 1)).toEqual(["seal-1"]);
  });

  it("accepts the same seal again and refuses a different one at that position", async () => {
    await store.put({ log, seq: 1, seal: "seal-1" });
    await expect(store.put({ log, seq: 1, seal: "forged" })).rejects.toBeInstanceOf(
      SealCopyConflictError,
    );
    expect(await store.list(log, 1)).toEqual(["seal-1"]);
  });

  it("refuses to delete the locked version, even for credentials allowed to delete", async () => {
    const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: keyOf(1) }));
    const refused = await client
      .send(new DeleteObjectCommand({ Bucket: bucket, Key: keyOf(1), VersionId: head.VersionId }))
      .then(
        () => undefined,
        (error: { $metadata?: { httpStatusCode?: number } }) => error.$metadata?.httpStatusCode,
      );
    expect(refused).toBe(403);
    expect(await store.list(log, 1)).toEqual(["seal-1"]);
  });

  it("still lists a seal hidden behind a delete marker, beside one put in its place", async () => {
    await store.put({ log, seq: 2, seal: "seal-2" });
    // Allowed under Object Lock: adds a delete marker; the locked version stays.
    await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: keyOf(2) }));
    await client.send(
      new PutObjectCommand({ Bucket: bucket, Key: keyOf(2), Body: "forged-2", IfNoneMatch: "*" }),
    );
    const listed = await store.list(log, 1);
    expect(listed).toEqual(expect.arrayContaining(["seal-1", "seal-2", "forged-2"]));
    expect(listed).toHaveLength(3);
  });
});

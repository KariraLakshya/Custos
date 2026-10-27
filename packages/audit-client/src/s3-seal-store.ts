import {
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  ListObjectVersionsCommand,
  PutObjectCommand,
  S3Client,
  type ListObjectVersionsCommandOutput,
} from "@aws-sdk/client-s3";
import {
  SealCopyConflictError,
  SealStoreMisconfiguredError,
  type SealStore,
} from "./seal-store.js";

/** The one method Custos uses; tests pass a stand-in (`@custos/audit-client/testing`). */
export type S3SealClient = Pick<S3Client, "send">;

// Copying runs one tick at a time, so a hung request would hold up every
// later copy; a slow S3 fails within seconds instead (as `createKmsClient`).
const CONNECTION_TIMEOUT_MS = 2_000;
const REQUEST_TIMEOUT_MS = 5_000;
const MAX_ATTEMPTS = 2;

/** A seal is a few hundred bytes; anything far larger is not one. */
const MAX_SEAL_BYTES = 16 * 1024;
const FETCH_CONCURRENCY = 16;
const SEQ_DIGITS = 20;

/**
 * An S3 client with bounded timeouts and retries. Credentials and region come
 * from the deployment's standard AWS configuration (`AWS_PROFILE`,
 * `AWS_REGION`, an instance role); nothing is contacted here.
 */
export function createS3SealClient(): S3SealClient {
  return new S3Client({
    maxAttempts: MAX_ATTEMPTS,
    requestHandler: {
      connectionTimeout: CONNECTION_TIMEOUT_MS,
      requestTimeout: REQUEST_TIMEOUT_MS,
    },
  });
}

/** `seals/<log DID, URI-encoded>/` — one folder per log, so logs never mix. */
function logPrefix(log: string): string {
  return `seals/${encodeURIComponent(log)}/`;
}

/** Zero-padded so S3's ascending key order is seq order. */
function sealKey(log: string, seq: number): string {
  return `${logPrefix(log)}${String(seq).padStart(SEQ_DIGITS, "0")}.json`;
}

function seqOfKey(prefix: string, key: string): number | undefined {
  const match = new RegExp(`^(\\d{${SEQ_DIGITS}})\\.json$`).exec(key.slice(prefix.length));
  return key.startsWith(prefix) && match ? Number(match[1]) : undefined;
}

function statusOf(error: unknown): number | undefined {
  return (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
}

/**
 * A `SealStore` in an S3 bucket with Object Lock (ADR 0017 §6, part 2b).
 *
 * `put` writes with `If-None-Match: *`, so a seal is never overwritten.
 * `list` reads every stored **version**, not the current listing: on a
 * versioned bucket anyone allowed `DeleteObject` can hide a locked seal behind
 * a delete marker and put a different one in its place. The original version
 * is still there under Object Lock, and listing versions returns both, so the
 * verifier sees two seals for one position and reports the rewrite.
 */
export function createS3SealStore(params: {
  readonly client: S3SealClient;
  readonly bucket: string;
}): SealStore & {
  /**
   * Whether the bucket is write-once: Object Lock on, with a default
   * COMPLIANCE retention. Throws `SealStoreMisconfiguredError` when S3
   * answers that it is not; returns "unreachable" when S3 cannot be asked.
   */
  checkWriteOnce(): Promise<"ok" | "unreachable">;
} {
  const { client, bucket } = params;

  async function read(key: string, versionId?: string): Promise<string> {
    const object = await client.send(
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        ...(versionId === undefined ? {} : { VersionId: versionId }),
      }),
    );
    if ((object.ContentLength ?? 0) > MAX_SEAL_BYTES) {
      throw new Error(`not a seal: ${key} is ${object.ContentLength} bytes`);
    }
    const body = (await object.Body?.transformToString("utf8")) ?? "";
    if (body.length > MAX_SEAL_BYTES) throw new Error(`not a seal: ${key} is too large`);
    return body;
  }

  return {
    async put({ log, seq, seal }) {
      const key = sealKey(log, seq);
      try {
        await client.send(
          new PutObjectCommand({
            Bucket: bucket,
            Key: key,
            Body: seal,
            ContentType: "text/plain; charset=utf-8",
            IfNoneMatch: "*",
          }),
        );
        return;
      } catch (error) {
        // 412: already stored. 409: another write raced this one. Either way,
        // what is stored now decides it.
        const status = statusOf(error);
        if (status !== 412 && status !== 409) throw error;
      }
      if ((await read(key)) !== seal) throw new SealCopyConflictError(log, seq);
    },

    async list(log, fromSeq) {
      const prefix = logPrefix(log);
      const found: { seq: number; key: string; versionId: string | undefined }[] = [];
      let keyMarker: string | undefined = sealKey(log, Math.max(0, fromSeq - 1));
      let versionIdMarker: string | undefined;
      for (;;) {
        const page: ListObjectVersionsCommandOutput = await client.send(
          new ListObjectVersionsCommand({
            Bucket: bucket,
            Prefix: prefix,
            ...(keyMarker === undefined ? {} : { KeyMarker: keyMarker }),
            ...(versionIdMarker === undefined ? {} : { VersionIdMarker: versionIdMarker }),
          }),
        );
        // Delete markers are not listed here: they hide nothing from this read.
        for (const version of page.Versions ?? []) {
          const seq = version.Key === undefined ? undefined : seqOfKey(prefix, version.Key);
          // Only the audit service writes under a log's folder; anything else
          // there is not a seal, and guessing past it would be failing open.
          if (seq === undefined) throw new Error(`not a seal: ${version.Key ?? "(no key)"}`);
          if (seq >= fromSeq) {
            found.push({ seq, key: version.Key!, versionId: version.VersionId });
          }
        }
        if (!page.IsTruncated) break;
        keyMarker = page.NextKeyMarker;
        versionIdMarker = page.NextVersionIdMarker;
        if (keyMarker === undefined) throw new Error("S3 listing truncated with no next marker");
      }
      found.sort((a, b) => a.seq - b.seq);
      const seals: string[] = [];
      for (let i = 0; i < found.length; i += FETCH_CONCURRENCY) {
        const batch = found.slice(i, i + FETCH_CONCURRENCY);
        seals.push(...(await Promise.all(batch.map((v) => read(v.key, v.versionId)))));
      }
      return seals;
    },

    async checkWriteOnce() {
      let configuration;
      try {
        configuration = await client.send(
          new GetObjectLockConfigurationCommand({ Bucket: bucket }),
        );
      } catch (error) {
        const status = statusOf(error);
        // S3 answered: no lock, no bucket, or no permission to ask. All are
        // set-up errors to fix before starting, not an outage to wait out.
        if (status !== undefined && status < 500) {
          throw new SealStoreMisconfiguredError(
            `${bucket}: ${(error as Error).name} (HTTP ${status})`,
          );
        }
        return "unreachable";
      }
      const lock = configuration.ObjectLockConfiguration;
      if (lock?.ObjectLockEnabled !== "Enabled") {
        throw new SealStoreMisconfiguredError(`${bucket} does not have Object Lock enabled`);
      }
      const retention = lock.Rule?.DefaultRetention;
      if (
        retention?.Mode !== "COMPLIANCE" ||
        !((retention.Days ?? 0) > 0 || (retention.Years ?? 0) > 0)
      ) {
        throw new SealStoreMisconfiguredError(
          `${bucket} has no default COMPLIANCE retention, so new seals would not be locked`,
        );
      }
      return "ok";
    },

    close: async () => {},
  };
}

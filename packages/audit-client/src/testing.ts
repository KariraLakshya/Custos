import {
  DeleteObjectCommand,
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  ListObjectsV2Command,
  ListObjectVersionsCommand,
  PutObjectCommand,
  type GetObjectLockConfigurationCommandOutput,
} from "@aws-sdk/client-s3";
import type { S3SealClient } from "./s3-seal-store.js";

type SentCommand =
  | DeleteObjectCommand
  | GetObjectCommand
  | GetObjectLockConfigurationCommand
  | ListObjectsV2Command
  | ListObjectVersionsCommand
  | PutObjectCommand;

/** One stored version of a key; `body` undefined is a delete marker. */
interface Version {
  readonly versionId: string;
  readonly body: string | undefined;
}

export interface FakeS3 {
  readonly client: S3SealClient;
  /** Every command received, in order. */
  readonly sent: SentCommand[];
  /** Versions by key, oldest first. */
  readonly objects: Map<string, Version[]>;
}

function s3Error(name: string, status: number): Error {
  return Object.assign(new Error(name), { name, $metadata: { httpStatusCode: status } });
}

/**
 * A stand-in for one versioned S3 bucket with Object Lock, as far as Custos's
 * seal store uses it: `If-None-Match: *` is checked against the current
 * version (a delete marker counts as no object, as on S3), a plain delete adds
 * a delete marker, and deleting a version is refused while it is locked (here:
 * always). Listings page `pageSize` entries at a time. For tests only
 * (`@custos/audit-client/testing`).
 */
export function fakeS3(
  options: {
    readonly pageSize?: number;
    /** What `GetObjectLockConfiguration` answers; an Error is thrown instead. */
    readonly lockConfiguration?:
      GetObjectLockConfigurationCommandOutput["ObjectLockConfiguration"] | Error;
    /** Called before each command; throw from it to fail that command. */
    readonly before?: (command: SentCommand) => void;
  } = {},
): FakeS3 {
  const pageSize = options.pageSize ?? 1000;
  const objects = new Map<string, Version[]>();
  const sent: SentCommand[] = [];
  let next = 0;

  const current = (key: string): Version | undefined => objects.get(key)?.at(-1);
  const sortedKeys = (prefix: string): string[] =>
    [...objects.keys()].filter((key) => key.startsWith(prefix)).sort();

  const client = {
    async send(command: SentCommand) {
      sent.push(command);
      options.before?.(command);

      if (command instanceof PutObjectCommand) {
        const key = command.input.Key ?? "";
        if (command.input.IfNoneMatch === "*" && current(key)?.body !== undefined) {
          throw s3Error("PreconditionFailed", 412);
        }
        const versionId = `v${++next}`;
        const body = String(command.input.Body);
        objects.set(key, [...(objects.get(key) ?? []), { versionId, body }]);
        return { VersionId: versionId };
      }

      if (command instanceof GetObjectCommand) {
        const key = command.input.Key ?? "";
        const versionId = command.input.VersionId;
        const version =
          versionId === undefined
            ? current(key)
            : objects.get(key)?.find((v) => v.versionId === versionId);
        if (version?.body === undefined) throw s3Error("NoSuchKey", 404);
        const body = version.body;
        return {
          ContentLength: Buffer.byteLength(body),
          VersionId: version.versionId,
          Body: { transformToString: async () => body },
        };
      }

      if (command instanceof DeleteObjectCommand) {
        const key = command.input.Key ?? "";
        if (command.input.VersionId !== undefined) throw s3Error("AccessDenied", 403);
        const versionId = `v${++next}`;
        objects.set(key, [...(objects.get(key) ?? []), { versionId, body: undefined }]);
        return { DeleteMarker: true, VersionId: versionId };
      }

      if (command instanceof ListObjectsV2Command) {
        const keys = sortedKeys(command.input.Prefix ?? "").filter(
          (key) => current(key)?.body !== undefined && key > (command.input.StartAfter ?? ""),
        );
        return { Contents: keys.map((Key) => ({ Key })), IsTruncated: false };
      }

      if (command instanceof ListObjectVersionsCommand) {
        // As S3: by key ascending, each key's versions newest first, markers included.
        const entries = sortedKeys(command.input.Prefix ?? "").flatMap((key) =>
          [...(objects.get(key) ?? [])].reverse().map((v) => ({ key, ...v })),
        );
        const keyMarker = command.input.KeyMarker;
        const versionMarker = command.input.VersionIdMarker;
        let start = 0;
        if (keyMarker !== undefined) {
          const at =
            versionMarker === undefined
              ? entries.findIndex((e) => e.key > keyMarker)
              : entries.findIndex((e) => e.key === keyMarker && e.versionId === versionMarker);
          start = at < 0 ? entries.length : versionMarker === undefined ? at : at + 1;
        }
        const page = entries.slice(start, start + pageSize);
        const truncated = start + pageSize < entries.length;
        const last = page.at(-1);
        return {
          Versions: page
            .filter((e) => e.body !== undefined)
            .map((e) => ({ Key: e.key, VersionId: e.versionId })),
          DeleteMarkers: page
            .filter((e) => e.body === undefined)
            .map((e) => ({ Key: e.key, VersionId: e.versionId })),
          IsTruncated: truncated,
          ...(truncated && last
            ? { NextKeyMarker: last.key, NextVersionIdMarker: last.versionId }
            : {}),
        };
      }

      // GetObjectLockConfigurationCommand
      const lock = options.lockConfiguration ?? {
        ObjectLockEnabled: "Enabled",
        Rule: { DefaultRetention: { Mode: "COMPLIANCE", Days: 1 } },
      };
      if (lock instanceof Error) throw lock;
      return { ObjectLockConfiguration: lock };
    },
  };

  return { client: client as unknown as S3SealClient, sent, objects };
}

export { s3Error as fakeS3Error };

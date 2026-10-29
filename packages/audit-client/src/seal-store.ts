import pg from "pg";
import type { S3SealClient } from "./s3-seal-store.js";

/**
 * Where copies of the audit ledger's seals are kept, outside the audit
 * database (ADR 0017 §6 and part 2a). A Postgres server today; S3 Object Lock
 * later, behind the same two calls.
 */
export interface SealStore {
  /**
   * Stores a copy. The same seal already stored at `(log, seq)` is fine; a
   * different one throws `SealCopyConflictError`, since two seals for one
   * position is evidence that history was rewritten.
   */
  put(copy: { readonly log: string; readonly seq: number; readonly seal: string }): Promise<void>;
  /** Every copy for `log` from `fromSeq` on, oldest first. */
  list(log: string, fromSeq: number): Promise<readonly string[]>;
  close(): Promise<void>;
}

export class SealCopyConflictError extends Error {
  constructor(
    readonly log: string,
    readonly seq: number,
  ) {
    super(`a different seal is already stored for ${log} at seq ${seq}`);
    this.name = "SealCopyConflictError";
  }
}

/** The seal store is not write-once (ADR 0017 part 2b): fix it before starting. */
export class SealStoreMisconfiguredError extends Error {
  constructor(reason: string) {
    super(`the S3 seal store is not write-once: ${reason}`);
    this.name = "SealStoreMisconfiguredError";
  }
}

/**
 * Opens the seal store at `url`: `postgres://` (part 2a) or `s3://<bucket>`
 * (part 2b, Object Lock). An S3 bucket is checked first: one that S3 says is
 * not write-once throws `SealStoreMisconfiguredError`; one that cannot be
 * reached is opened anyway, and its first read or write fails instead. The
 * URL may hold a password, so no error repeats it. The S3 client is loaded
 * only for an `s3://` URL.
 */
export async function openSealStore(
  url: string,
  options: { readonly s3Client?: S3SealClient } = {},
): Promise<SealStore> {
  const scheme = url.slice(0, Math.max(0, url.indexOf(":")));
  if (scheme === "postgres" || scheme === "postgresql") return createPostgresSealStore(url);
  if (scheme !== "s3") throw new Error(`unsupported seal store URL scheme: ${scheme || "(none)"}`);
  const parsed = new URL(url);
  if (
    parsed.hostname === "" ||
    (parsed.pathname !== "" && parsed.pathname !== "/") ||
    parsed.search !== "" ||
    parsed.username !== ""
  ) {
    throw new Error("an S3 seal store URL is s3://<bucket>, nothing more");
  }
  const { createS3SealClient, createS3SealStore } = await import("./s3-seal-store.js");
  const store = createS3SealStore({
    client: options.s3Client ?? createS3SealClient(),
    bucket: parsed.hostname,
  });
  await store.checkWriteOnce();
  return store;
}

/**
 * A `SealStore` on its own Postgres server, `infra/seal-store/schema.sql`.
 * Connect as `custos_sealer` (the audit service: add and read only) or
 * `custos_auditor` (read only). The URL holds a password: never log it.
 */
export function createPostgresSealStore(url: string): SealStore {
  const pool = new pg.Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 5_000 });
  // An idle connection dropped by the server must not crash the process.
  pool.on("error", () => {});
  return {
    async put({ log, seq, seal }) {
      await pool.query(
        "INSERT INTO audit_seal_copies (log, seq, seal) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        [log, seq, seal],
      );
      const stored = await pool.query<{ seal: string }>(
        "SELECT seal FROM audit_seal_copies WHERE log = $1 AND seq = $2",
        [log, seq],
      );
      if (stored.rows[0]?.seal !== seal) throw new SealCopyConflictError(log, seq);
    },
    async list(log, fromSeq) {
      const result = await pool.query<{ seal: string }>(
        "SELECT seal FROM audit_seal_copies WHERE log = $1 AND seq >= $2 ORDER BY seq",
        [log, fromSeq],
      );
      return result.rows.map((row) => row.seal);
    },
    close: () => pool.end(),
  };
}

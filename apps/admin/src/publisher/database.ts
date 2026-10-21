import pg from "pg";

/**
 * Reads A's revoked agents straight from its database, as one input to the
 * publisher's union. The point of the publisher is to work when A is switched
 * off, and a switched-off database host can leave a connection hanging far past
 * the publish lock's stale limit, so every wait here has an explicit timeout.
 * The caller treats any failure as "left out, with a warning".
 */
export function createDatabaseIndexReader(
  connectionString: string,
  options: { readonly timeoutMs: number },
): { read: () => Promise<number[]>; close: () => Promise<void> } {
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0) {
    throw new Error("timeoutMs must be a positive whole number of milliseconds");
  }
  const pool = new pg.Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: options.timeoutMs,
    query_timeout: options.timeoutMs,
    statement_timeout: options.timeoutMs,
  });
  // A dropped idle connection must not crash the process.
  pool.on("error", () => undefined);

  return {
    async read() {
      const revoked = await pool.query<{ status_list_index: number }>(
        "SELECT status_list_index FROM status_list_entries WHERE revoked_at IS NOT NULL",
      );
      const external = await pool.query<{ status_list_index: number }>(
        "SELECT status_list_index FROM external_revoked_indexes",
      );
      return [...revoked.rows, ...external.rows].map((row) => row.status_list_index);
    },
    close: () => pool.end(),
  };
}

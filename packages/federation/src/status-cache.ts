import {
  applyStatusList,
  verifyForeignStatusList,
  type TrustAnchor,
  type VerifiedForeignStatusList,
} from "@custos/core";
import type { ConfiguredAnchor } from "./anchors.js";

/** What the cache tells its embedder, for logging. Never carries a response body. */
export type StatusCacheEvent =
  | {
      readonly kind: "updated";
      readonly domain: string;
      readonly validFrom: string;
      readonly notAfter: string;
    }
  | { readonly kind: "not-modified"; readonly domain: string }
  | { readonly kind: "failed"; readonly domain: string; readonly reason: string };

export interface StatusCache {
  /** The latest verified list for an anchor, or `undefined` if none has been fetched. */
  viewFor(anchor: TrustAnchor): VerifiedForeignStatusList | undefined;
  /** One fetch for one enabled anchor; a call while one is in flight joins it. */
  pollOnce(anchor: ConfiguredAnchor): Promise<void>;
  /** Polls every enabled anchor now and then every interval. Resolves after the first round. */
  start(): Promise<void>;
  /** Aborts in-flight fetches and waits, promptly, for the loops to end. */
  stop(): Promise<void>;
}

interface AnchorState {
  view: VerifiedForeignStatusList | undefined;
  /** Validators from the last body that *verified*, never from a rejected one. */
  etag: string | undefined;
  lastModified: string | undefined;
  inFlight: Promise<void> | undefined;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
// A real list is a few KiB; core refuses a list credential over 1 MiB anyway.
const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_VALIDATOR_LENGTH = 256;

/** Reads at most `maxBytes`, counting what actually arrives, abortable at any point. */
async function readCapped(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error("body too large");
  if (response.body === null) throw new Error("no body");

  const reader = response.body.getReader();
  const aborted = new Promise<never>((_, reject) => {
    const fail = (): void => reject(new Error("aborted"));
    if (signal.aborted) fail();
    else signal.addEventListener("abort", fail, { once: true });
  });
  // The race can lose, leaving this promise to reject later with nobody waiting.
  aborted.catch(() => undefined);

  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await Promise.race([reader.read(), aborted]);
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maxBytes) throw new Error("body too large");
      chunks.push(next.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function validator(value: string | null): string | undefined {
  return value !== null && value.length > 0 && value.length <= MAX_VALIDATOR_LENGTH
    ? value
    : undefined;
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const done = (): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  });
}

/**
 * Keeps B's view of each trusted organisation's signed status list (ADR 0014),
 * off the hot path: the gate only reads `viewFor`, which never touches the
 * network. Fetches only the URL in the anchor configuration, never one taken
 * from a credential; follows no redirects; caps the body as it arrives; and
 * trusts nothing it fetched until `verifyForeignStatusList` has checked it
 * against the pinned key and a fresh signed time.
 *
 * Failure keeps the last verified view. It is not extended: the view's own
 * signed expiry then makes B deny (`STATUS_STALE`), which is the bounded
 * staleness the architecture asks for. A restart loses the view, and B denies
 * (`STATUS_UNAVAILABLE`) until the first poll succeeds.
 */
export function createStatusCache(params: {
  readonly anchors: readonly ConfiguredAnchor[];
  /** Explicit configuration, no default. */
  readonly pollIntervalMs: number;
  /** How far the publisher's clock may be ahead of ours. Explicit, no default. */
  readonly maxClockSkewSeconds: number;
  readonly now: () => Date;
  readonly fetchImpl?: typeof fetch;
  readonly requestTimeoutMs?: number;
  readonly maxBodyBytes?: number;
  readonly onEvent?: (event: StatusCacheEvent) => void;
}): StatusCache {
  const { anchors, pollIntervalMs, maxClockSkewSeconds, now, onEvent } = params;
  const fetchImpl = params.fetchImpl ?? fetch;
  const requestTimeoutMs = params.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const maxBodyBytes = params.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs <= 0) {
    throw new Error("pollIntervalMs must be a positive integer");
  }

  const stopper = new AbortController();
  const states = new Map<string, AnchorState>();
  for (const anchor of anchors) {
    states.set(anchor.credentialIssuerDid, {
      view: undefined,
      etag: undefined,
      lastModified: undefined,
      inFlight: undefined,
    });
  }
  let loops: Promise<void>[] = [];

  function emit(event: StatusCacheEvent): void {
    try {
      onEvent?.(event);
    } catch {
      // Logging must never decide whether the cache works.
    }
  }

  async function fetchAndVerify(anchor: ConfiguredAnchor, state: AnchorState): Promise<void> {
    const failed = (reason: string): void =>
      emit({ kind: "failed", domain: anchor.domain, reason });

    // Conditional only while a verified view is held: a 304 must have
    // something to mean "unchanged" about.
    const headers: Record<string, string> = { accept: "application/json" };
    if (state.view !== undefined) {
      if (state.etag !== undefined) headers["if-none-match"] = state.etag;
      if (state.lastModified !== undefined) headers["if-modified-since"] = state.lastModified;
    }
    const signal = AbortSignal.any([stopper.signal, AbortSignal.timeout(requestTimeoutMs)]);

    let response: Response;
    let credential: unknown;
    try {
      response = await fetchImpl(anchor.statusFetchUrl, { headers, redirect: "error", signal });
      if (response.status === 304) {
        if (state.view === undefined) return failed("unexpected 304");
        return emit({ kind: "not-modified", domain: anchor.domain });
      }
      if (!response.ok) return failed(`HTTP ${response.status}`);
      credential = JSON.parse(await readCapped(response, maxBodyBytes, signal));
    } catch (error) {
      return failed(error instanceof Error ? error.message : "fetch failed");
    }

    const verified = await verifyForeignStatusList({
      credential,
      anchor,
      now: now(),
      maxClockSkewSeconds,
    });
    if (!verified.ok) return failed(verified.error.code);

    state.view = applyStatusList(state.view, verified.value);
    state.etag = validator(response.headers.get("etag"));
    state.lastModified = validator(response.headers.get("last-modified"));
    emit({
      kind: "updated",
      domain: anchor.domain,
      validFrom: state.view.validFrom.toISOString(),
      notAfter: state.view.notAfter.toISOString(),
    });
  }

  function pollOnce(anchor: ConfiguredAnchor): Promise<void> {
    const state = states.get(anchor.credentialIssuerDid);
    if (state === undefined || !anchor.enabled) return Promise.resolve();
    state.inFlight ??= fetchAndVerify(anchor, state)
      .catch((error: unknown) => {
        emit({
          kind: "failed",
          domain: anchor.domain,
          reason: error instanceof Error ? error.message : "poll failed",
        });
      })
      .finally(() => {
        state.inFlight = undefined;
      });
    return state.inFlight;
  }

  return {
    viewFor(anchor) {
      return states.get(anchor.credentialIssuerDid)?.view;
    },
    pollOnce,
    async start() {
      if (loops.length > 0) return;
      const firsts: Promise<void>[] = [];
      loops = anchors
        .filter((anchor) => anchor.enabled)
        .map((anchor) => {
          let firstDone!: () => void;
          firsts.push(new Promise<void>((resolve) => (firstDone = resolve)));
          return (async () => {
            await pollOnce(anchor);
            firstDone();
            // A timeout chain, not an interval: the next wait starts only after
            // this fetch ended, so polls never pile up behind a slow host.
            while (!stopper.signal.aborted) {
              await sleep(pollIntervalMs, stopper.signal);
              if (!stopper.signal.aborted) await pollOnce(anchor);
            }
          })();
        });
      await Promise.all(firsts);
    },
    async stop() {
      stopper.abort();
      await Promise.all(loops);
    },
  };
}

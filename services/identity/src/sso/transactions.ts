import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Scope } from "@custos/control-plane-auth";

/** What an operator's terminal gets back once, after a successful login. */
export interface CompletedLogin {
  readonly operatorKey: string;
  readonly name: string;
  readonly expiresAt: Date;
}

export type LoginFailure =
  "NO_MAPPED_GROUP" | "NO_READ_SCOPE" | "TOKEN_REJECTED" | "PROVIDER_ERROR";

export type LoginStatus =
  | { readonly state: "pending" }
  | { readonly state: "complete"; readonly login: CompletedLogin }
  | { readonly state: "failed"; readonly reason: LoginFailure }
  | { readonly state: "unknown" };

/**
 * A dashboard login (ADR 0022 §4) the company login has accepted, waiting
 * for its one-time code. Only the code's SHA-256 is kept; no key exists yet.
 */
export interface AwaitingRelease {
  readonly codeHash: Buffer;
  readonly codeExpiresAt: number;
  readonly name: string;
  readonly scopes: readonly Scope[];
}

interface Transaction {
  readonly loginId: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
  readonly returnTo: string | undefined;
  expiresAt: number;
  outcome: LoginStatus;
  release?: AwaitingRelease;
}

export interface PendingLogin {
  readonly loginId: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
  /** Set only for a dashboard login; fixed when the login starts. */
  readonly returnTo?: string;
}

/**
 * In-flight SSO logins (ADR 0010 §2): the `state`, `nonce` and PKCE
 * verifier for each, server-side only, for `ttlMs`. In memory, so correct
 * for one identity instance (like the vault's replay cache). Bounded: when
 * full, new logins are refused rather than evicting someone else's.
 */
export interface LoginTransactions {
  start(values: Omit<PendingLogin, "loginId">): PendingLogin | null;
  /** The pending login a provider redirect names, by its `state`. */
  findByState(state: string): PendingLogin | null;
  finish(loginId: string, outcome: LoginStatus): void;
  /**
   * A terminal login's completed outcome is returned once, then forgotten.
   * A dashboard login is never released here: it answers `unknown` and is
   * left as it was.
   */
  take(loginId: string): LoginStatus;
  /** A dashboard login accepted by the company login: waits for its code until `codeExpiresAt`. */
  awaitRelease(loginId: string, release: AwaitingRelease): void;
  /**
   * One attempt per login: the login is forgotten whatever the outcome, so
   * a wrong, replayed or expired code can never be retried. Returns the
   * accepted login's name and scopes only when `codeHash` matches.
   */
  release(
    loginId: string,
    codeHash: Buffer,
  ): { readonly name: string; readonly scopes: readonly Scope[] } | null;
}

export function createLoginTransactions(options: {
  readonly clock: { now(): Date };
  readonly ttlMs?: number;
  readonly maxPending?: number;
}): LoginTransactions {
  const ttlMs = options.ttlMs ?? 5 * 60_000;
  const maxPending = options.maxPending ?? 1_000;
  const byId = new Map<string, Transaction>();
  const now = (): number => options.clock.now().getTime();

  function sweep(): void {
    const at = now();
    for (const [id, tx] of byId) if (tx.expiresAt <= at) byId.delete(id);
  }

  return {
    start(values) {
      sweep();
      if (byId.size >= maxPending) return null;
      const loginId = randomBytes(16).toString("hex");
      byId.set(loginId, {
        loginId,
        state: values.state,
        nonce: values.nonce,
        codeVerifier: values.codeVerifier,
        returnTo: values.returnTo,
        expiresAt: now() + ttlMs,
        outcome: { state: "pending" },
      });
      return { ...values, loginId };
    },

    findByState(state) {
      sweep();
      for (const tx of byId.values()) {
        if (tx.state === state && tx.outcome.state === "pending" && tx.release === undefined) {
          return {
            loginId: tx.loginId,
            state: tx.state,
            nonce: tx.nonce,
            codeVerifier: tx.codeVerifier,
            ...(tx.returnTo === undefined ? {} : { returnTo: tx.returnTo }),
          };
        }
      }
      return null;
    },

    finish(loginId, outcome) {
      const tx = byId.get(loginId);
      if (tx) tx.outcome = outcome;
    },

    take(loginId) {
      sweep();
      const tx = byId.get(loginId);
      if (!tx || tx.returnTo !== undefined) return { state: "unknown" };
      if (tx.outcome.state !== "pending") byId.delete(loginId);
      return tx.outcome;
    },

    awaitRelease(loginId, release) {
      const tx = byId.get(loginId);
      if (!tx || tx.returnTo === undefined) return;
      tx.release = release;
      // The login lives exactly as long as its code.
      tx.expiresAt = release.codeExpiresAt;
    },

    release(loginId, codeHash) {
      sweep();
      const tx = byId.get(loginId);
      if (!tx) return null;
      byId.delete(loginId);
      const awaiting = tx.release;
      if (awaiting === undefined || awaiting.codeExpiresAt <= now()) return null;
      if (
        codeHash.length !== awaiting.codeHash.length ||
        !timingSafeEqual(codeHash, awaiting.codeHash)
      ) {
        return null;
      }
      return { name: awaiting.name, scopes: awaiting.scopes };
    },
  };
}

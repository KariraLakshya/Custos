import { randomBytes } from "node:crypto";

/** What an operator's terminal gets back once, after a successful login. */
export interface CompletedLogin {
  readonly operatorKey: string;
  readonly name: string;
  readonly expiresAt: Date;
}

export type LoginFailure = "NO_MAPPED_GROUP" | "TOKEN_REJECTED" | "PROVIDER_ERROR";

export type LoginStatus =
  | { readonly state: "pending" }
  | { readonly state: "complete"; readonly login: CompletedLogin }
  | { readonly state: "failed"; readonly reason: LoginFailure }
  | { readonly state: "unknown" };

interface Transaction {
  readonly loginId: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
  readonly expiresAt: number;
  outcome: LoginStatus;
}

export interface PendingLogin {
  readonly loginId: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
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
  /** A completed login is returned once, then forgotten. */
  take(loginId: string): LoginStatus;
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
        ...values,
        loginId,
        expiresAt: now() + ttlMs,
        outcome: { state: "pending" },
      });
      return { ...values, loginId };
    },

    findByState(state) {
      sweep();
      for (const tx of byId.values()) {
        if (tx.state === state && tx.outcome.state === "pending") {
          return {
            loginId: tx.loginId,
            state: tx.state,
            nonce: tx.nonce,
            codeVerifier: tx.codeVerifier,
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
      if (!tx) return { state: "unknown" };
      if (tx.outcome.state !== "pending") byId.delete(loginId);
      return tx.outcome;
    },
  };
}

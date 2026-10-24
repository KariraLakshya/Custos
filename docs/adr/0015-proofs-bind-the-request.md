# 0015: Proofs of possession are bound to the tool and action

**Status:** Proposed 2026-10-24, extended 2026-10-25 to the vault at the founder's request. Built on branch `feat/foreign-proof-binds-action`; accepted when the founder merges it. Resolves the open item ADR 0014 recorded at steps 1 and 4 ("the proof does not bind the request"), and the same gap found in the vault's token-request proof (ADR 0007).

## Context

An agent proves it holds its own key with a short statement signed by that key (a proof of possession). Two kinds of proof ask for something:

- **A call into another organisation** (ADR 0014 decision 2): addressed to the receiving organisation B.
- **A token request to the vault** (ADR 0007 decision 3): addressed to the vault's `/tokens` URL, asking for a 60-second token for one tool and one action.

Until now both signed only four claims: `typ`, `aud`, `iat` (time) and `jti` (a unique id). Neither said **what** the request was for. A proof captured in flight (a compromised proxy, a log that recorded a request) could therefore be spent once, within the skew window and before the real agent, on a **different** tool or action: at B, any action B serves; at the vault, a token for any other tool the agent is granted. ADR 0007 had recorded that the vault's `aud` covers the request's method and URL, but the tool and action travel in the body. The replay guards stop a second use, not a first use by someone else.

## Decision

1. **Both proofs name the request.** Foreign-call and token-request proofs carry two more signed claims, `tool` and `action`, each a non-empty string of at most 128 characters (the audit schema's bound; the vault's `/tokens` body is bounded the same, so the two always agree). `buildForeignCallProof` and `buildTokenRequestProof` take `request: { tool, action }` and refuse anything else.
2. **The binding cannot be skipped.** These two types are verified only by `verifyForeignCallProof` and `verifyTokenRequestProof`, which require the expected request and fail on any mismatch (`WRONG_REQUEST`). The general `verifyPossessionProof` refuses both types outright, so a verifier that reaches for it gets a refusal, not an unbound check. Registration proofs are unchanged.
3. **Old-format proofs are refused.** A correctly signed proof of either type without `tool` and `action` is `MALFORMED_PROOF`. Nothing is deployed, so there is no fallback; the `typ` strings are unchanged.
4. **Comparison is exact.** No case folding or trimming: what the agent signed is what the receiver must be about to do.
5. **Checked before the replay guard.** A proof presented for the wrong request is refused without its `jti` being recorded, so an attacker's misuse does not use up the agent's real call.
6. **Where the expected request comes from.** At the vault, it is the tool and action of the token about to be issued (the same values the token is then bound to). At B, `verifyForeignAgent` takes a required `request`, and `createForeignAgentGate().check()` requires `tool` and `action`. They must come from B's own routing (the endpoint or operation it is serving), **never** from a field the caller sets: a value the caller chooses would let it pick whatever its proof was made for, and bind nothing.
7. **Public answers unchanged.** A mismatch is a proof failure: at the vault `401 INVALID_PROOF_OF_POSSESSION` (reason `WRONG_REQUEST`), at B `401 UNAUTHORIZED`; logged, never audited (ADR 0008's rule for authentication failures).

## What is not bound (accepted)

**The request body.** "Read customer 1" and "read customer 2" under the same tool and action are interchangeable within the window. A captured proof can still be spent once, on the same tool and action, with any body, if it reaches the receiver before the real agent. This is the line DPoP (RFC 9449) draws: it binds method and URL, not the body. **Accepted by the founder on 2026-10-25.** The full fix, if ever wanted, is a digest of the body or channel binding.

## Consequences

- Every caller passes the request: the SDK's `connect(agent, tool).call(action)` signs `{ tool, action }`, and the CLI goes through the SDK. The e2e test and the federation demo use one shared constant for what the agent signs and what B runs, so they cannot drift.
- Tests: tool mismatch, action mismatch, case and whitespace differences, old format, non-string claims, an empty or oversized request on the builders and verifiers, the general verifier refusing both types, each type refused as the other, the signature checked before the request, a wrong-request proof not used up (vault and B), the vault's HTTP 401 and its 128-character body bound, an e2e call signed for `write` presented as `read` (401, no audit record). Mutations of the comparison, the old-format refusal, the general-verifier refusal and B's request shape check are all caught; removing the comparison also fails the e2e.
- Threat model §5: B's first accepted gap and the vault's captured-request gap are both narrowed to the unbound body, accepted.

# Architecture: hot path and cold path

Custos is four small services, a dashboard and two command-line tools. This page shows what each piece does and the one rule that shapes them all: **the work done on every tool call stays local and fast; everything else may be slow.**

## The pieces

```text
            operator (custos CLI, SDK, custos-admin)
                 │  register        │ grant, store tool password     │ revoke
                 ▼                  ▼                                ▼
            ┌──────────┐      ┌───────────┐   signed revocation  ┌────────────┐
            │ identity │      │   vault   │ ◄──── notice (push) ─│ revocation │
            │  :4001   │      │   :4002   │ ── status list ────► │   :4003    │
            └──────────┘      └───────────┘     (resync, pull)   └────────────┘
                 │ reserve a        │ ▲  │                             │
                 │ revocation slot ─┼─┼──┼─────────────────────────────┘
                 ▼                  │ │  │ call with the real password
            every service ──────────┼─┼──┼──► audit :4004 (sealed ledger)
                                    │ │  ▼
       agent: credential + proof ───┘ │  tool (Stripe, mock-database, …)
       agent: 60 s token + action ────┘
```

| Piece                    | Job                                                                                                                        |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| **identity**             | Registers agents and signs their credentials with its issuer key. Publishes its public key at `/.well-known/did.json`.     |
| **vault**                | Holds tool passwords (encrypted), checks agents, issues 60-second tokens, makes tool calls. Keeps a local revocation view. |
| **revocation**           | Records revocations, signs and pushes them to vaults, and publishes the signed status list.                                |
| **audit**                | Appends every reported decision to a hash-chained ledger and seals it every 10 seconds.                                    |
| **dashboard**            | A live view of allow and deny decisions and revoked agents. A monitoring view, not a verifier.                             |
| **`custos`**             | The CLI for operators and agents. [Reference](/reference/cli).                                                             |
| **`custos-admin`**       | For whoever runs Custos: API keys, the demo, the cross-organisation publisher. Talks to the database directly.             |
| **`@custos/sdk`**        | The same lifecycle from code. [Reference](/reference/sdk).                                                                 |
| **`@custos/federation`** | For an organisation that accepts another's agents. [Federation](/concepts/federation).                                     |

All four services share one Postgres database in this development build (see [Not yet production-hardened](/security/limits)).

## Hot path and cold path

The **hot path** is what runs on every agent request to a tool: `POST /call` on the vault. It checks the agent's token signature, the token's expiry and the vault's in-memory revocation view, then calls the tool. **It never calls another Custos service.** Ed25519 signature checks take microseconds and the revocation view is a local copy, so a slow or unreachable control plane never slows a tool call.

The **cold path** is everything else: registering, granting, storing tool passwords, issuing tokens, revoking, and writing audit records. These happen less often and may take longer.

## Four rules that follow

**Push, don't pull.** When an agent is revoked, the revocation service pushes a signed notice into every vault's local view. The hot path reads that view; it never asks the revocation service on a call.

**Verification is local and works offline.** A verifier checks a credential with the issuer's public key, which it fetched once and keeps. It does not need the issuer to be up. This is what lets another organisation keep checking your agents while your services are off ([Federation](/concepts/federation)).

**Fail closed, with bounded staleness.** If Custos cannot be sure an answer is safe, it refuses. A vault whose revocation view has not been refreshed for `REVOCATION_MAX_STALENESS_MS` (30 seconds by default) refuses every call rather than risk letting a revoked agent through. The limit is explicit configuration, never an accident.

**Audit writes never block a request.** Services report decisions to the audit service without waiting for an answer. No request waits on an audit write.

## Where the code lives

| Directory                     | What it holds                                                                           |
| ----------------------------- | --------------------------------------------------------------------------------------- |
| `packages/core`               | Signatures, DIDs, credentials, tokens, the ledger and delegation checks. No I/O at all. |
| `packages/contracts`          | Shared schemas, error codes and the [refusal catalogue](/reference/refusals).           |
| `packages/sdk`                | The developer SDK.                                                                      |
| `packages/connectors`         | One adapter per tool.                                                                   |
| `packages/control-plane-auth` | API keys, scopes, lockout and mTLS checks.                                              |
| `packages/federation`         | The receiving side of cross-organisation trust.                                         |
| `packages/kms`                | The AWS KMS signer.                                                                     |
| `services/*`                  | identity, vault, revocation, audit.                                                     |
| `apps/*`                      | `cli`, `admin`, `dashboard`, and this documentation site (`docs`).                      |

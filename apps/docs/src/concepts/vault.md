# The vault

The vault is the service that holds the real tool passwords. Its job is **dispossession**: agents never hold raw tool keys, so a compromised agent has nothing long-lived to leak.

## What it stores

An operator stores a tool's credential once, for example a Stripe test-mode key:

```bash
pnpm --filter @custos/vault seed stripe sk_test_...
```

The script reads the operator key from `CUSTOS_OPERATOR_KEY` (and the vault address from `VAULT_URL`, default `http://localhost:4002`) and stores the credential through `POST /credentials`, which needs the `credentials:write` scope. (`pnpm demo` stores the two stand-in tools, `mock-database` and `mock-slack`, for you; they accept any secret.)

The vault encrypts each credential with **XChaCha20-Poly1305** under `VAULT_MASTER_KEY`, a 32-byte key from its environment, and stores the ciphertext and nonce in Postgres (ADR 0004). The plaintext exists only in memory, for the moment of a tool call, and is never logged or returned. A test checks that neither the token response nor the call response ever contains the secret.

::: warning Keep the master key
A vault restarted with a different `VAULT_MASTER_KEY` cannot decrypt what it stored: calls fail with `500 invalid tag`. Store the tool credentials again. There is one master key for every credential, with no rotation yet.
:::

## How a call works

1. The agent asks for a [scoped token](/concepts/scoped-tokens) and proves it holds its key.
2. The agent sends the token, action and input to `POST /call`.
3. The vault checks the token and the revocation view, decrypts the tool credential, and calls the tool through its **connector**.
4. It returns `{ "result": ... }` and reports the outcome to the audit service, without waiting for it.

The agent sees the tool's result, never the credential.

## Connectors

A connector is the vault's adapter for one tool. Three ship today:

| Tool            | Actions          | Data categories         | Notes                                  |
| --------------- | ---------------- | ----------------------- | -------------------------------------- |
| `mock-database` | `query`          | `internal-records`      | Stand-in; accepts any secret           |
| `mock-slack`    | `post-message`   | `messaging-content`     | Stand-in; accepts any secret           |
| `stripe`        | `list-customers` | `payment-customer-data` | Real Stripe API; needs a test-mode key |

**Data categories** are a fixed declaration per connector of what kind of data the tool can touch. They are written into each audit record. Custos does not inspect, filter or mask what a tool returns.

Connectors also honour revocation themselves, so a revoked agent is refused by the adapter even if a call reached it.

## What the vault does not stop

The vault makes sure an agent never gets a tool credential **from Custos**. It does not stop an agent calling a tool directly with a credential it got somewhere else. Network enforcement for that (a sidecar, then eBPF egress rules) is planned work, not built.

Sources: ADR 0004, ADR 0005, ADR 0006.

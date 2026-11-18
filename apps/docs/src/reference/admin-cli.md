# `custos-admin` CLI

`custos-admin` is for whoever runs Custos. It manages API keys, starts the local demos, and runs the cross-organisation publisher. It talks to the **database directly** (`DATABASE_URL`, default `postgres://custos:custos@localhost:5433/custos`), which is deliberate: there is no web endpoint for creating keys.

Run it from the repository root after `pnpm build`:

```bash
pnpm -s custos-admin <command>       # or: node apps/admin/dist/bin.js <command>
```

`custos-admin <command> --help` prints a command's options. `pnpm demo` and `pnpm demo:federation` run `demo` and `demo-federation` after migrating and building.

## `key create`

Create an API key. The key is printed once and can't be retrieved again.

| Option                    | Default      | Meaning                                                                                                                      |
| ------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `--kind <kind>`           | **required** | `operator` or `service`                                                                                                      |
| `--name <name>`           | **required** | Who or what holds the key, for the audit trail                                                                               |
| `--scopes <scopes>`       | **required** | Comma-separated: `credentials:write`, `policies:write`, `agents:revoke`, `agents:register`, `audit:write`, `status:allocate` |
| `--expires-in <duration>` | `90d`        | Lifetime, such as `90d` or `12h`                                                                                             |

Service-only scopes (`audit:write`, `status:allocate`) are refused on operator keys. See [Control-plane authentication](/concepts/control-plane-auth#scopes).

## `key list`

List keys, never their secrets.

## `key revoke <id>`

Revoke a key by id (from `key list` or `key create`). It stops working on its next use.

## `dev-keys`

Create a local development key set: one operator key and the identity, revocation and vault service keys. Prints four lines ready to paste, and says which terminal each goes in.

| Option                    | Default | Meaning                                                 |
| ------------------------- | ------- | ------------------------------------------------------- |
| `--shell <shell>`         | `bash`  | `bash` or `powershell`: the syntax of the printed lines |
| `--expires-in <duration>` | `90d`   | Lifetime, such as `90d` or `12h`                        |

## `demo`

Start all five local services with generated keys and the stand-in tools. Run it as `pnpm demo`, which migrates and builds first. Seeds and keys are generated in memory (a valid `IDENTITY_ISSUER_SEED`, `REVOCATION_SIGNING_SEED`, `VAULT_MASTER_KEY` or `AUDIT_SIGNING_SEED` already in the environment is reused). Its API keys expire in 12 hours and are revoked when you press Ctrl-C. It refuses to start if a port it needs is taken.

## `demo-federation`

Two organisations on this machine: A's agents checked by B, A switched off, one agent revoked. Run it as `pnpm demo:federation`. See [Trust another organisation](/how-to/federation).

## `publish-status`

Sign and publish organisation A's revocation status list from this machine, for other organisations to read ([Federation](/concepts/federation)). The signing key comes from the environment only: `CUSTOS_PUBLISHER_SIGNING_SEED` (development, the same seed as A's `REVOCATION_SIGNING_SEED`), or `CUSTOS_PUBLISHER_KEY_PROVIDER=kms` with `CUSTOS_PUBLISHER_KMS_KEY_ID` (the revocation service's KMS key).

`init`, `once`, `run` and `revoke` share these options:

| Option                         | Meaning                                                           |
| ------------------------------ | ----------------------------------------------------------------- |
| `--domain <domain>`            | Domain the revocation DID is published under, such as `a.example` |
| `--dir <dir>`                  | Where the journal, last signed state and lock are kept            |
| `--out <file>`                 | The file a static server publishes (written atomically)           |
| `--validity-seconds <n>`       | How long each list is promised good for. No default               |
| `--max-clock-skew-seconds <n>` | How far a source list's time may be ahead. Default 5              |
| `--host-url <url>`             | Also read the list from this host, to recover from it             |
| `--use-database`               | Also read A's revoked agents from `DATABASE_URL` (optional)       |

### `publish-status init`

Start a new publisher, once. Refused if a list signed by this key already exists.

| Option                           | Meaning                                                                               |
| -------------------------------- | ------------------------------------------------------------------------------------- |
| `--confirm-nothing-is-published` | State that this publisher has never published (otherwise give `--host-url`, to check) |

### `publish-status once`

Re-sign and publish once (a stamp).

### `publish-status run`

Re-sign every `--stamp-seconds` until stopped.

| Option                | Meaning                                                             |
| --------------------- | ------------------------------------------------------------------- |
| `--stamp-seconds <n>` | How often to re-sign; shorter than `--validity-seconds`. No default |

The stamp must also be shorter than every receiver's window (A's `REVOCATION_PUBLISHED_MAX_AGE_SECONDS`, each B's `maxStatusAgeSeconds`). Nothing can check that for you.

### `publish-status revoke`

Revoke one agent, permanently, and publish it.

| Option                              | Meaning                                                               |
| ----------------------------------- | --------------------------------------------------------------------- |
| `--credential <file>`               | The agent's credential file (preferred)                               |
| `--index <n>`                       | The agent's status-list index (fallback; also pass `--confirm-index`) |
| `--confirm-index <n>`               | The same index again                                                  |
| `--operator <name>`                 | **Required.** Who is revoking, for the journal                        |
| `--reason <text>`                   | **Required.** Why, for the journal                                    |
| `--identity-did <did>`              | A's identity service DID, to check the credential against             |
| `--identity-public-key <multibase>` | A's identity service key, from its DID document                       |

### `publish-status show`

Print the publisher's DID, list address and public key, to check against A's DID document.

| Option              | Meaning                                              |
| ------------------- | ---------------------------------------------------- |
| `--domain <domain>` | Domain the revocation DID is published under         |
| `--dir <dir>`       | The publisher's directory (to count journal entries) |

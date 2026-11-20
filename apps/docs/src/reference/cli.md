# `custos` CLI

The `custos` command registers agents, grants tools, uses them, delegates, revokes, and checks the audit log. It is the `@custos/cli` workspace package; after `pnpm build` run it as `node apps/cli/dist/bin.js` (or make an alias, as in [Your first agent](/get-started/first-agent)).

`custos` on its own prints the lifecycle in order, eight steps ending with `custos status`. `custos help <command>` or `custos <command> --help` prints a command's options. `custos --version` prints the version.

## Conventions

**Naming an agent.** `grant --to`, `delegate --to`, `revoke`, `status` and `audit-log [agent]` take an agent's **id** (as `register` printed it) or its **DID**. Never its name, which can repeat. An id becomes a DID under `--identity-issuer` (default `did:web:localhost%3A4001`); anything that is neither is refused before a request is sent.

**Operator key.** `register`, `grant` and `revoke` are operator commands. They read the key from `CUSTOS_OPERATOR_KEY`, or else from the file `custos login` wrote (`~/.custos/operator.key`, or `CUSTOS_OPERATOR_KEY_FILE`). Never from a flag. `audit-log` sends the same key when it finds one; the audit log can still be read without one today, but it will need `audit:read` once that read closes.

**Refusals.** A refused request prints three lines to stderr and exits 1:

```text
Refused: <what happened>          (or "Problem:" when something is actually wrong)
Next: <what to do>
Code: <CODE> (<REASON>)
```

A server error (not a 401 or 403) adds a `Detail:` line. A mistake the CLI catches itself prints `error: <message>` and `Next: <fix>`. See [Refusal codes](/reference/refusals).

**Files.** `register` and `delegate` never overwrite an existing file.

## `login`

Sign in as an operator with your company account (SSO). Needs an identity service configured for SSO ([how-to](/how-to/operator-sso)).

```text
custos login [options]
```

| Option                 | Default                                                  | Meaning                                            |
| ---------------------- | -------------------------------------------------------- | -------------------------------------------------- |
| `--identity-url <url>` | `http://localhost:4001`                                  | Identity service base URL                          |
| `--key-file <path>`    | `~/.custos/operator.key` (or `CUSTOS_OPERATOR_KEY_FILE`) | Where to keep the session's operator key           |
| `--no-browser`         |                                                          | Print the sign-in URL instead of opening a browser |

The key is saved owner-only and never printed.

## `register`

Register a new agent and issue its identity credential. Operator command (`agents:register`).

```text
custos register [options]
```

| Option                 | Default                 | Meaning                                                                                                                                                                |
| ---------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--identity-url <url>` | `http://localhost:4001` | Identity service base URL                                                                                                                                              |
| `--name <name>`        |                         | A name to show beside the agent: 1 to 64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit. Not unique; commands still take the id |
| `--out <path>`         | `agent.json`            | Where to write the credential                                                                                                                                          |
| `--key-out <path>`     | `agent.key`             | Where to write the private key (owner-only)                                                                                                                            |
| `--json`               |                         | Print the result as JSON (the agent, plus `keyFile` and `credentialFile`; never the private key)                                                                       |

The key pair is generated locally; the private key is never sent or printed. If registration fails, both files are removed.

## `verify`

Independently verify an agent's identity credential: fetches the issuer's DID document fresh and checks the signature.

```text
custos verify <credentialFile>
```

Prints `verified: credential is authentic`, or `rejected: <reason>` on stderr with exit code 1.

## `use`

Request a scoped vault token for a tool action and immediately call it.

```text
custos use [options] <tool> <action>
```

| Option                | Default                 | Meaning                                                              |
| --------------------- | ----------------------- | -------------------------------------------------------------------- |
| `--credential <path>` | `agent.json`            | The agent's credential file                                          |
| `--key <path>`        | `agent.key`             | The agent's private key; proves this is the agent                    |
| `--vault-url <url>`   | `http://localhost:4002` | Vault base URL. Must match the vault's `VAULT_PUBLIC_URL` exactly    |
| `--input <json>`      | `{}`                    | JSON input for the action                                            |
| `--delegation <path>` |                         | Act on permission another agent passed to this one (from `delegate`) |

Prints `{ "result": ... }` on success.

## `delegate`

Pass some of this agent's permission to another agent, signed with this agent's key. Nothing is sent anywhere.

```text
custos delegate [options] <tool> <actions...>
```

| Option                    | Default                    | Meaning                                                     |
| ------------------------- | -------------------------- | ----------------------------------------------------------- |
| `--to <agent>`            | **required**               | The receiving agent's id or DID                             |
| `--credential <path>`     | `agent.json`               | This (delegating) agent's credential file                   |
| `--key <path>`            | `agent.key`                | This agent's private key                                    |
| `--identity-issuer <did>` | `did:web:localhost%3A4001` | The identity service's DID; turns an agent id into its DID  |
| `--ttl <seconds>`         | 600                        | How long it lasts; never past what it extends               |
| `--depth <n>`             | 0                          | How many more times it may be passed on (0: not at all)     |
| `--extending <path>`      |                            | A delegation this agent received and is passing on          |
| `--out <path>`            | `delegation.json`          | Where to write it, for the other agent's `use --delegation` |

`--ttl` and `--depth` must be whole numbers. See [Delegation](/concepts/delegation).

## `grant`

Give an agent one tool; without this every call is refused. Operator command (`policies:write`).

```text
custos grant [options] <tool>
```

| Option                    | Default                    | Meaning                                                    |
| ------------------------- | -------------------------- | ---------------------------------------------------------- |
| `--to <agent>`            |                            | The agent's id or DID                                      |
| `--credential <path>`     |                            | Or: the agent's credential file (the older way to name it) |
| `--identity-issuer <did>` | `did:web:localhost%3A4001` | Turns an agent id into its DID                             |
| `--vault-url <url>`       | `http://localhost:4002`    | Vault base URL                                             |
| `--json`                  |                            | Print the result as JSON                                   |

Give exactly one of `--to` and `--credential`. There is no default agent.

## `revoke`

Cut an agent off from every tool it can reach. This cannot be undone. Operator command (`agents:revoke`). Alias: `deprovision`.

```text
custos revoke [options] <agent>
```

| Option                   | Default                 | Meaning                                    |
| ------------------------ | ----------------------- | ------------------------------------------ |
| `--revocation-url <url>` | `http://localhost:4003` | Revocation service base URL                |
| `--reason <text>`        |                         | Why this agent is being cut off (recorded) |
| `--json`                 |                         | Print the result as JSON                   |

Prints how many vaults were told straight away (`Vaults told now: N.`), and a `Problem:` line if some could not be reached. Then `Next: custos status <id>` to confirm the cut-off.

## `status`

Show one agent: its name and who registered it, the tools it may use, whether it is cut off (when, by whom and why), and its recent actions from the verified audit log. Needs an operator key with all four read scopes (`agents:read`, `policies:read`, `revocations:read`, `audit:read`).

```text
custos status [options] <agent>
```

| Option                    | Default                     | Meaning                                                            |
| ------------------------- | --------------------------- | ------------------------------------------------------------------ |
| `<agent>`                 |                             | The agent's id or DID                                              |
| `--identity-url <url>`    | `http://localhost:4001`     | Identity service base URL                                          |
| `--vault-url <url>`       | `http://localhost:4002`     | Vault base URL                                                     |
| `--revocation-url <url>`  | `http://localhost:4003`     | Revocation service base URL                                        |
| `--audit-url <url>`       | `http://localhost:4004`     | Audit service base URL                                             |
| `--identity-issuer <did>` | `did:web:localhost%3A4001`  | The identity service's DID; turns an agent id into its DID         |
| `--seal-file <path>`      | `~/.custos/audit-seal.json` | Shared with `audit-log`                                            |
| `--accept-key <key>`      |                             | An audit seal key you have checked, as for `audit-log`. Repeatable |
| `--json`                  |                             | Print the result as JSON                                           |

If one service can't be read, that part says "could not check" and names the service (and, on a `401`, the scope the key needs); it never reports an unchecked part as "not revoked" or "no grants". A tampered audit log is shown as an alarm. Exits 0 only when all four parts were read and the log verified; an unknown agent is an error with a `Next:` line.

## `audit-log`

Pull and independently verify the sealed audit log, for one agent or every agent.

```text
custos audit-log [options] [agent]
```

| Option                    | Default                     | Meaning                                                                                                                    |
| ------------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `[agent]`                 |                             | Show only this agent's entries: its id or DID                                                                              |
| `--audit-url <url>`       | `http://localhost:4004`     | Audit service base URL                                                                                                     |
| `--seal-file <path>`      | `~/.custos/audit-seal.json` | Where the newest verified seal and the accepted keys are remembered between checks                                         |
| `--accept-key <key>`      |                             | A seal key you have checked with the audit service's operator (after `KEY_CHANGED` or `UNTRUSTED_KEY`). Repeat for several |
| `--identity-issuer <did>` | `did:web:localhost%3A4001`  | The identity service's DID; delegation chains in the log are re-verified against it                                        |

| Environment variable          | Meaning                                                                                                                          |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `CUSTOS_AUDIT_SEAL_STORE_URL` | The outside seal store, as a read-only user: `postgres://…` or `s3://<bucket>`. Environment only, because it can hold a password |

Prints the verified log as JSON on stdout (`verified`, `headSeq`, `sealedThrough`, `unsealedCount`, `records`, `outsideSealsChecked`, …), each verified delegation chain on stderr as `#<seq> <issued|call>: <chain>`, and exits 1 if verification fails. See [The audit ledger](/concepts/audit-ledger).

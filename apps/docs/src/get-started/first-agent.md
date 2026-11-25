# Your first agent (CLI)

This walkthrough takes one agent through its whole life with the `custos` command: register it, watch it be refused, grant it one tool, use the tool without ever seeing its password, let it hand work to a helper, cut it off, and check the signed record of all of it.

It assumes `pnpm demo` is running ([Install and run](/get-started/installation)).

## 1. Set up a terminal

Open a **new terminal in an empty directory**. `register` writes two files and never overwrites existing ones, so an empty directory avoids clashes with an earlier run.

Make `custos` a shortcut, using the path to your clone (`pnpm demo` prints this line with the path filled in):

::: code-group

```bash [bash / zsh]
alias custos="node /path/to/Custos/apps/cli/dist/bin.js"
```

```powershell [PowerShell]
function custos { node "C:\path\to\Custos\apps\cli\dist\bin.js" @args }
```

:::

Set the operator key `pnpm demo` printed. Operator commands (`register`, `grant`, `revoke`) read it from the environment only, never from a command-line flag, so it stays out of your shell history:

::: code-group

```bash [bash / zsh]
export CUSTOS_OPERATOR_KEY=custos_operator_...
```

```powershell [PowerShell]
$env:CUSTOS_OPERATOR_KEY = "custos_operator_..."
```

:::

Run `custos` on its own to see the steps in order.

::: info Signing in instead of a key
`custos login` signs an operator in with a company account instead of a key. It needs an identity service configured for SSO, which `pnpm demo` does not set up. See [Operator sign-in (SSO)](/how-to/operator-sso). Without it, use `CUSTOS_OPERATOR_KEY` as above.
:::

## 2. Register an agent

```bash
custos register --name billing-bot
```

```text
Registered billing-bot (id 3f2b8c1e-...).
Its credential is in agent.json and its private key in agent.key. Keep the key secret.
Next: custos grant <tool> --to 3f2b8c1e-...
```

The CLI made the agent's key pair **on your machine**, proved to the identity service that it holds the private key, and got back a credential signed by the identity service. Two files:

- **`agent.key`**: the agent's private key. It is never sent to Custos and never printed.
- **`agent.json`**: the agent's credential. On its own it is useless to anyone who copies it, because every request must also be signed with `agent.key`.

The name is optional and only shown beside the agent. Names don't have to be unique, so every command takes the **id**. Keep it for the next steps.

## 3. Check the credential yourself

```bash
custos verify agent.json
```

```text
verified: credential is authentic
```

This fetches the identity service's public key document fresh and checks the signature itself, rather than trusting the service's word.

## 4. Try a tool: refused

Custos denies by default. Being registered doesn't mean being allowed.

```bash
custos use mock-database query --input '{"table":"customers"}'
```

```text
Refused: This agent has not been given this tool.
Next: To allow it, an operator runs: custos grant mock-database --to 3f2b8c1e-...
Code: POLICY_DENIED
```

Every refusal has this shape: what happened, what to do next, and a code you can look up in [Refusal codes](/reference/refusals).

## 5. Grant one tool, then use it

```bash
custos grant mock-database --to <id>
custos use mock-database query --input '{"table":"customers"}'
```

```text
Agent 3f2b8c1e-... may now use mock-database.
Next, as the agent: custos use mock-database <action>
{
  "result": [
    { "id": 1, "name": "Ada Lovelace" },
    { "id": 2, "name": "Alan Turing" }
  ]
}
```

Behind that one `use` command, the agent showed its credential to the vault, **signed the request with `agent.key`**, and got a pass valid for 60 seconds for this one tool and action. The vault then called the tool with the real password. The agent never saw it.

The grant covers only that tool. `custos use mock-slack post-message --input '{"channel":"#ops","text":"hi"}'` is still refused with `POLICY_DENIED`.

## 6. Hand part of the access to a helper

Register a second agent with its own files, then have the first agent pass on only `query` on the database:

```bash
custos register --out helper.json --key-out helper.key
custos delegate mock-database query --to <helper id>
```

```text
Agent <helper id> may now query on mock-database for this agent. Give it delegation.json.
Next, as that agent: custos use mock-database query --delegation delegation.json
```

`delegate` signs a hand-off with the first agent's key and writes it to `delegation.json`. Nothing is sent anywhere. The helper uses it with its own credential and key:

```bash
custos use mock-database query --credential helper.json --key helper.key --delegation delegation.json
```

The helper has no grant of its own: it acts on the first agent's, and only for what was passed on. Anything else is refused with `Code: DELEGATION_DENIED (NOT_COVERED)`. The hand-off lasts 10 minutes by default (`--ttl`), and the helper may not pass it on unless you allow it (`--depth`).

## 7. Revoke the agent

```bash
custos revoke <id> --reason "compromised"
```

```text
Agent 3f2b8c1e-... is cut off from every tool. This cannot be undone.
Vaults told now: 1.
Next: custos status <id>   (to confirm)
```

"Vaults told now: 1" means the signed revocation notice reached the vault straight away. The dashboard shows the agent as cut off. (`deprovision` is the older name of this command and still works.)

Try again, and it is refused everywhere. The helper is cut off too, because it was acting for this agent:

```bash
custos use mock-database query --input '{"table":"customers"}'
```

```text
Refused: This agent, or an agent it is acting for, has been cut off from every tool.
Next: A revoked agent cannot be restored. Register a new one with: custos register
Code: AGENT_REVOKED
```

## 8. Check the audit record

```bash
custos audit-log
```

Every attempt above, allowed or refused, is in the log, and so are your own operator actions (register, grant, revoke), each naming the key that did it. The CLI checks the whole hash chain against the newest seal and against the seal it remembered from its last check, prints the verified log as JSON, and exits non-zero if anything was edited, removed or rewritten. Each delegated entry is re-checked and printed as a chain, from the operator who granted the tool through each agent, such as `#12 issued: <operator> → <agent DID> → <helper DID>`. Pass an agent's id or DID to see only that agent: `custos audit-log <id>`.

To also check the copies of the seals on the separate seal store, set its read-only address (`pnpm demo` prints it):

```bash
export CUSTOS_AUDIT_SEAL_STORE_URL=postgres://custos_auditor:custos_auditor@localhost:5434/custos_seals
```

Without it the CLI prints a note and `"outsideSealsChecked": false`.

::: tip After a restart: KEY_CHANGED
Each `pnpm demo` run seals with a new audit key. The first `custos audit-log` after a restart stops with `KEY_CHANGED` and shows the new key. Compare it with the `audit seal key` line `pnpm demo` printed (never with the audit service's own `/.well-known/did.json`, which the service controls), then accept it once: `custos audit-log --accept-key <key>`.
:::

## 9. Check one agent

```bash
custos status <id>
```

```text
billing-bot (id 3f2b8c1e-...)
  Registered 2026-11-20T10:00:00.000Z by demo-dev-operator.
  May use:
    mock-database, granted 2026-11-20T10:01:00.000Z by demo-dev-operator
  Cut off: yes, at 2026-11-20T10:05:00.000Z by demo-dev-operator.
  Reason: compromised
  Recent actions, newest first (the audit log verified):
  ...
Next: custos audit-log 3f2b8c1e-...   (every recorded action, verified)
```

One command answers "who is this, what may it do, is it cut off, and what has it done?" It asks identity, the vault, the revocation service and the audit log, each with your operator key, and checks the audit log the same way `custos audit-log` does. If one of them can't be read, that part says "could not check" and names the service; it never shows an unchecked part as "not revoked". A tampered audit log is shown as an alarm. See the [`status` reference](/reference/cli#status).

## Next

- Do the same from code: [SDK quickstart](/get-started/sdk-quickstart).
- Every command and option: [custos CLI reference](/reference/cli).

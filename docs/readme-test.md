# README test: brief for the tester

Thanks for helping. Custos is a trust layer for AI agents. We need to know whether a developer who has never seen it can get it running from the README alone. **You are testing the README, not your own skill.** Every place you get stuck is a bug in our docs, and that's exactly what we want to find.

## The rules

- Use **only** [the README](../README.md), from "Quickstart: zero to a revoked agent" through the end of step 4. Step 5 (the SDK) is optional.
- **Don't ask the author for help while you're doing it.** If you're stuck for more than 10 minutes, write down where and why, then use the README's Troubleshooting table. If that doesn't get you moving again, stop. That's a valid result.
- Run commands as written. If you have to change one to make it work, note what you changed.

## What you need

About 30–45 minutes, plus:

- Node 22 or later
- pnpm 9 (`npm install -g pnpm@9.15.0`)
- Docker Desktop (or Docker Engine), running
- bash/zsh, or PowerShell 7+ on Windows

## Pass criteria

You pass if you see all of these, in order:

| Step | You should see                                                              |
| ---- | --------------------------------------------------------------------------- |
| 4    | `custos verify agent.json` prints `verified: credential is authentic`       |
| 4    | The first `custos use mock-database …` prints `denied: POLICY_DENIED`       |
| 4    | After `custos grant`, the same command returns Ada Lovelace and Alan Turing |
| 4    | `custos use mock-slack …` prints `denied: POLICY_DENIED`                    |
| 4    | `custos deprovision` shows `"delivered": 1`                                 |
| 4    | `custos use mock-database …` then prints `denied: AGENT_REVOKED`            |
| 4    | `custos audit-log` lists your actions and exits without an error            |
| 2    | The dashboard at http://localhost:4005 shows the decisions as they happen   |

## What to write down

Copy this and fill it in as you go:

```
OS and shell:
Node / pnpm / Docker versions:
Start time:
Finished? (yes / stopped at step __):
Total time:

For each problem:
  Step:
  What I ran:
  What I expected:
  What happened (paste the error):
  How I got past it (or didn't):

Anything confusing, even if you figured it out:
```

## Sending results

Open an issue at https://github.com/KariraLakshya/Custos/issues titled "README test: <your name>", or email kariralakshya68@gmail.com. Never paste the keys that `custos-admin dev-keys` prints: they're secrets, even though they're only for local use.

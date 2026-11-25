# Introduction

Custos is a trust layer for AI agents. It gives every agent a cryptographic identity, keeps real tool passwords out of agents entirely, lets each agent use only the tools it has been granted, cuts a compromised agent off from every tool in well under a second, and keeps a signed record of everything it did that anyone can check.

## Why it exists

An AI agent that calls tools (a payments API, a database, a chat workspace) usually does it with a long-lived API key pasted into its environment. That key is a problem in three ways:

- **Anyone who copies it is the agent.** Logs, prompts and repositories leak keys.
- **It can do anything the key can do,** not only what this agent's job needs.
- **Taking it back is slow.** You rotate the key at every tool, by hand, while the agent may still be running.

Custos removes the key from the agent. The agent proves who it is with its own private key, asks Custos for a short-lived pass for one tool and one action, and Custos makes the call with the real password, which the agent never sees.

## Where it sits

Protocols such as MCP (Model Context Protocol) and A2A (Agent2Agent) define **how agents talk** to tools and to each other. Custos decides **whether an agent should be trusted and what it may do**. It runs on top of those protocols rather than replacing them, much as TLS runs underneath the web without replacing HTTP.

## The six questions

Custos is designed to answer six questions on every agent request. Five are built; one is not.

| Question                                     | What answers it today                                                                                                                                                           | Built? |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **Who are you?** (identity)                  | A `did:web` identifier and a credential signed by your identity service.                                                                                                        | Yes    |
| **Can I trust you?** (authentication)        | Every request for a pass is signed with the agent's own private key.                                                                                                            | Yes    |
| **What may you do?** (authorization)         | Deny by default; an operator grants one tool at a time.                                                                                                                         | Yes    |
| **What data may you receive?** (data policy) | **Not built.** Each tool declares a fixed list of data categories, which is written into the audit record, but Custos does not filter, mask or inspect the data a tool returns. | **No** |
| **Can I revoke you?** (lifecycle)            | A signed revocation pushed to every vault, with a status list as the durable record.                                                                                            | Yes    |
| **Can I prove what happened?** (audit)       | A hash-chained, sealed ledger that `custos audit-log` re-checks.                                                                                                                | Yes    |

## What you get today

- A `custos` command-line tool and a TypeScript SDK (`@custos/sdk`).
- Four small services you run yourself: **identity**, **vault**, **revocation** and **audit**, plus a live dashboard.
- `custos-admin`, a command for whoever runs Custos: API keys, the one-command demo, and the cross-organisation publisher.
- Optional: service-to-service certificates (mTLS), operator sign-in with a company account (SSO), signing keys in AWS KMS, container images.

## What's real and what's planned {#real-vs-planned}

::: warning A development build
Custos is early-stage. It runs end to end on one machine and every security control has a test that proves it fails safely, but **nothing here is hardened for production** and nothing is hosted yet. Not yet production-hardened lists the gaps.
:::

Built and on `main`:

- Agent identity, proof of possession, scoped tokens, the vault, grants, revocation, the sealed audit ledger, delegation between agents, and cross-organisation federation (proven by an end-to-end test on one machine).
- The issuer, revocation and audit signing keys can live in AWS KMS. The vault's own token key is in memory.

Not built:

- Data filtering, masking or classification (the data-policy question above).
- A sidecar next to each agent, network (eBPF) enforcement that stops an agent calling a tool directly, and Kubernetes deployment. These are the next phases.
- A hosted Custos service.
- A way to remove a single grant: today you revoke the agent instead.
- Agent names are shown only; nothing looks an agent up by name.

## Next

- [Install and run Custos](/get-started/installation), then [walk an agent through its life](/get-started/first-agent).
- New to the vocabulary? The [glossary](/glossary) explains each term once.
- Found a security problem? Please report it privately, as described in [SECURITY.md](https://github.com/KariraLakshya/Custos/blob/main/SECURITY.md).

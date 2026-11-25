---
layout: home

hero:
  name: Custos
  text: A trust layer for AI agents
  tagline: MCP and A2A define how agents talk. Custos decides whether an agent should be trusted and what it may do.
  actions:
    - theme: brand
      text: Get started
      link: /get-started/installation
    - theme: alt
      text: What is Custos?
      link: /introduction
    - theme: alt
      text: Reference
      link: /reference/cli

features:
  - title: An identity for every agent
    details: Each agent gets a did:web identifier and a W3C verifiable credential signed by your identity service. Anyone can check it without asking Custos.
  - title: No tool keys in agents
    details: The vault holds the real tool passwords. An agent gets a 60-second pass for one tool and one action, and never sees the password.
  - title: Cut off in under a second
    details: Revoking an agent pushes a signed notice to every vault at once. A vault that cannot confirm it is up to date refuses rather than guesses.
  - title: A record you can check
    details: Every decision goes into a hash-chained audit log, sealed every 10 seconds and copied to a store the audit service cannot rewrite.
  - title: Delegation with provenance
    details: An agent can pass part of its access to a helper agent with a signed hand-off. The log records the whole chain, from the person who granted the tool.
  - title: Across organisations
    details: Organisation B can accept agents that organisation A issued, and keep refusing A's revoked agents, even while A is switched off.
---

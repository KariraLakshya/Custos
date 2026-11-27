# Custos — the dashboard plan (Phase 8b)

_What the operator sees, screen by screen. Design decisions are in ADR 0022 (§4 sign-in, §5 the audit check, §6 grey and red); the path through the product is in `docs/user-journey.md`. This file is the target the dashboard steps are built and tested against._

## What it must pass

From `docs/build-plan.md`, Phase 8b DONE:

1. **Five seconds.** After five seconds a newcomer can say whether anything is wrong, and which agent was cut off.
2. **Prove it.** They can show the proof in the audit record without help.
3. **Who it acts for.** They can say who an agent is acting for, from its delegation chain.

## Rules for every screen

- **Words first.** Every panel opens with a sentence ("All clear", "billing-bot was cut off 5 s ago"), not a number or a code.
- **Names first.** Show "billing-bot" and "alice@company.com". The DID, id, hash or key is one click away. An agent with no name shows as "unnamed · …a1b2".
- **Grey is normal, red is a problem.** A refusal or a cut-off agent is Custos working, so it is grey. Red is only for: a service not answering, out-of-date revocation information, a failed signature check, a tampered audit record. Green is used only for "All clear" and "Verified". Colour always comes with an icon and words, never on its own.
- **Read-only.** There are no buttons that change anything. Each place where something could be done shows the command instead ("To give it a tool: `custos grant …`").
- **Nothing before sign-in.** Signed out, the page holds no data at all.

## Screen 0 — Sign in

```
┌──────────────────────────────────────────────┐
│  CUSTOS                                      │
│                                              │
│  Sign in with your company account to see    │
│  your agents.                                │
│                                              │
│  [ Sign in ]                                 │
└──────────────────────────────────────────────┘
```

- **Signed in, but the group may see nothing:** "Signed in as bob@company.com. Your group cannot see anything here. Ask whoever runs Custos to add your group." Plus a Sign out link.
- **Sign-in failed:** the reason in words, from the refusal catalogue, and a "Try again" button.

## Header (on every screen after sign-in)

```
CUSTOS    [ Now ]  Who can do what   Proof         alice@company.com · Sign out
```

A thin strip under the header turns red only when a service is down. It says which one, for example: "The audit service is not answering. Proof cannot be checked."

## Screen 1 — Now: "Is anything wrong right now?"

```
┌──────────────────────────────────────────────────────────────────┐
│  ✓ All clear                                                     │
│    Every service answering · revocation list checked 3 s ago     │
├──────────────────────────────────────────────────────────────────┤
│  Cut off recently                                                │
│  ⊘ billing-bot   cut off 5 s ago by alice@company.com            │
│                  "compromised"                                   │
├──────────────────────────────────────────────────────────────────┤
│  Refused in the last hour: 3   (normal, Custos doing its job)  ▸ │
│    14:02  billing-bot asked for stripe: not given this tool      │
│    14:05  billing-bot asked for mock-database: cut off           │
├──────────────────────────────────────────────────────────────────┤
│  Services    ● identity  ● vault  ● revocation  ● audit          │
├──────────────────────────────────────────────────────────────────┤
│  Other companies' agents          (only when federation is on)   │
└──────────────────────────────────────────────────────────────────┘
```

- **The headline is the five-second answer.** It reads "✓ All clear", or "⚠ 2 problems need attention", followed by one line per problem with its next step. For example: "Revocation service not answering for 40 s. Check that it is running." When an agent was cut off in the last 24 hours, a grey line under the headline names the newest one: "billing-bot was cut off 5 s ago by alice@company.com" (founder, 2026-11-27). The headline stays "All clear", because a cut-off is intended.
- **"Cut off recently"** lists revoked agents, newest first, each with who did it, when, and the reason given. A new entry is highlighted for 10 seconds (it replaces today's toast). It is grey: a cut-off is intended.
- **Refusals** are a grey count with a sentence for each, taken from the catalogue. Forged or broken passes are counted here too (founder, 2026-11-13), as one line, over the same last hour: "12 forged or broken passes". If the vault started less than an hour ago, the line adds "since the vault started at 14:01". They come from the vault's in-memory count, not the audit log, so they have no proof link and no agent name (ADR 0022 §6, founder 2026-11-27), and they stay grey however many there are. Clicking any other refusal opens Proof filtered to that agent, with the entry marked (founder, 2026-11-27).
- **Updates:** about every 2 seconds, as today.
- **The federation panel** is today's "Across organisations", moved here. Its content is unchanged in this phase.

## Screen 2 — Who can do what: "Who may do what, and for whom?"

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Agent          Acting for                     May use                   │
│  billing-bot    alice@company.com              mock-database             │
│                                                 (given by alice, 12 Nov) │
│  helper-bot     alice@company.com → billing-bot   mock-database: query   │
│                                                 (passed on, until 14:20) │
│  ─ cut off ─                                                             │
│  old-bot        —                              no longer usable          │
│                 cut off 10 Nov by alice@company.com                      │
└──────────────────────────────────────────────────────────────────────────┘
```

- **"Acting for"** shows the delegation chain in plain words: person → agent → agent. Chains appear once they have been used, because hand-offs that were never presented are not stored anywhere (ADR 0022 §5). The column header says "chains in use".
- **Clicking a name** opens a side panel with: the id, the DID, when it was registered and by whom, each grant with its date, and the last five actions. This is the same information as `custos status`.
- **Cut-off agents** sit at the bottom, greyed out, with when and by whom.
- **A search box** filters by name.
- **Updates:** about every 10 seconds. Grants change rarely.

## Screen 3 — Proof: "What happened, and can I prove it?"

```
┌──────────────────────────────────────────────────────────────────┐
│  ✓ Verified                                                      │
│    142 entries · none changed since they were sealed             │
│    last sealed 14:02 · 3 newer entries not sealed yet            │
│    The dashboard checks this itself and starts fresh when it     │
│    restarts. For an independent check: custos audit-log          │
├──────────────────────────────────────────────────────────────────┤
│  [ all agents ▾ ]                                                │
│  14:06  alice@company.com cut off billing-bot ("compromised")    │
│  14:05  billing-bot asked for mock-database: refused, cut off    │
│  14:03  helper-bot queried mock-database for                     │
│         alice@company.com → billing-bot: allowed                 │
│  14:01  alice@company.com gave billing-bot mock-database         │
└──────────────────────────────────────────────────────────────────┘
```

- **The result is one of these:**
  - "✓ Verified" (green);
  - "✗ Tampered" (red), with what was found in words, for example "entry #57 does not match its seal", and the next step;
  - "Needs a person": a new seal key, with the `--accept-key` instruction;
  - "Cannot check right now" (red), when the audit service is not answering.
- **Every event is one sentence.** Clicking it shows the raw record, its hash and the signature check for that entry.
- **The filter** narrows the list to one agent. That covers DONE point 2, showing proof for the agent that was cut off.
- **Updates:** the check runs about every 15 seconds, because it reads the whole record.

## States every screen handles

| State                        | What the person sees                                                          |
| ---------------------------- | ----------------------------------------------------------------------------- |
| Loading, first time          | "Checking…" in place of the headline, never an empty table                    |
| Data's service not answering | Red line naming the service, and the last good data greyed with "as of 14:02" |
| Group may not see this view  | "Your group cannot see grants. Ask whoever runs Custos."                      |
| Nothing yet (new install)    | The first-visit screen below, in place of all three views                     |
| Session expired              | Sign-in screen, with "Your sign-in ran out. Sign in again."                   |

## First visit — no agents yet (founder, 2026-11-15)

Someone who signs in before registering any agent must never see empty tables. They see a start screen that walks them through the lifecycle:

```
┌──────────────────────────────────────────────────────────────────┐
│  Welcome, alice@company.com. You have no agents yet.             │
│  Four steps, about five minutes:                                 │
│                                                                  │
│  ○ 1  Register an agent     custos register --name billing-bot  ⧉│
│  ○ 2  Give it a tool        custos grant mock-database --to …   ⧉│
│  ○ 3  Let it make a call    custos use mock-database query      ⧉│
│  ○ 4  Cut it off            custos revoke billing-bot           ⧉│
│                                                                  │
│  ┌ What this page will look like ─────────────── EXAMPLE ┐       │
│  │  (the Now view, faded, with made-up agents)            │       │
│  └────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────┘
```

- **Each step ticks itself** from the real reads (an agent exists, a grant exists, an allowed call is in the audit log, a revocation exists). After step 1 the normal views appear and the checklist shrinks to a strip at the top until step 4 is ticked or dismissed.
- **⧉ copies the command.** Still read-only: the page shows commands, it never runs them.
- **Registering from code.** Under the four steps: "Registering many agents? Your own code can do it with the SDK: `custos.register()`." with a link to the docs site's SDK quickstart. Each agent's key is then made where the agent runs. There is no Register button: the dashboard stays read-only in Phase 8b, so an agent's key never passes through a browser and a stolen dashboard session can only look (founder, 2026-11-27). A button, or the registration assistant, is reconsidered after the stranger runs.
- **The example is labelled EXAMPLE on the panel itself**, faded, and never mixed into the real views. A security screen must not show a made-up "All clear" or a made-up agent that could be mistaken for a real one.
- **Shown only when the answer really is "none".** If the agent read was refused (the group may not see agents) or the identity service is not answering, the person sees that state instead. "No agents" must never hide "cannot see agents".
- **Per view, after the first agent:** Now with nothing refused says "Nothing refused in the last hour"; Proof with an empty log says "No entries yet. The first one appears when an agent makes a call."

Tests: the start screen appears only for an empty, successful agent read; a refused or failed read shows its own state; the example panel never renders inside a real view.

## What changes from today's page

| Today                                               | Planned                                                          |
| --------------------------------------------------- | ---------------------------------------------------------------- |
| "Denied" count and rows in red                      | Grey, counted, with a sentence for each                          |
| Service addresses typed into boxes, then "Connect"  | Gone: the dashboard's own back end knows the addresses           |
| Agents shown as shortened DIDs                      | Names, with the DID one click away                               |
| No sign-in; the browser reads the services directly | Company sign-in; the browser reads only the dashboard's back end |
| Records shown without checking them                 | Proof view with a verified or tampered result                    |
| One long page                                       | Three views, Now first                                           |

## How it is tested

- **Each view from recorded fixtures.** A real sealed audit record is recorded as test fixtures in four versions: clean, tampered, truncated and delegated. Each view's sentences are checked against them: the headline, the cut-off line, the chain, and the verified or tampered result.
- **Escaping.** A name such as `<script>` is shown as text, never run.
- **Signed out.** Every data route answers nothing, and the page has no data.
- **Grey versus red.** A refusal never produces red; a stale revocation list always does.
- **A stranger run.** It covers moments 6 to 8 of `docs/user-journey.md`.

## Decided

- **An outage gets its own red label (founder, 2026-11-15).** When the vault cannot reach the identity service, the refusal gets its own code with severity alarm, in place of today's `INVALID_AGENT_CREDENTIAL`. Now's headline counts it as a problem, and the CLI says to check the service, not the agent. Built in Phase 8b step 3 and added to ADR 0022 §6 in that PR. The agent is refused either way.

- **Look: match the landing page (founder, 2026-11-16).** Ink background, brass accent, serif headings, so Custos looks like one product.
- **A clickable preview with made-up data comes before the build (founder, 2026-11-16).**
- **The registration assistant is planned after Phase 8b (founder, 2026-11-16).** A person describes an agent in plain words and gets a proposal to check. It sees only that sentence and the list of tool names and actions, never keys, ids, audit records or other agents. It is not part of Phase 8b and needs its own ADR.

- **"Recent" on Now (founder, 2026-11-16):** the last hour for refusals, the last 24 hours for cut-offs. Older items stay in Proof and in "Who can do what".
- **The first preview was rejected as too AI-looking (founder, 2026-11-16).** It applied the landing page's colours and fonts to rounded panels. The look is redone when the dashboard page is built, alongside the other Phase 8b steps.
- **The dashboard journey, step by step (founder reviewed 2026-11-27).** Ten main-path steps and ten "something went wrong" branches, in `docs/user-journey.md` under "On the dashboard". The founder chose, all as recommended: the headline names a cut-off for 24 hours; forged passes are counted by the vault in memory and stay grey (ADR 0022 §6); clicking a refusal opens Proof for that agent; the dashboard stays read-only, with a line pointing to the SDK for registering from code.

## Decisions for the founder

1. **Look.** There are two options. One keeps today's dark theme, tidied. The other matches the landing page: ink, brass and serif headings. Recommendation: match the landing page, so Custos looks like one product.
2. **What "recent" means on Now.** Recommendation: the last hour for refusals, and the last 24 hours for cut-offs.
3. **A clickable preview before building.** This would be a mock with made-up data, the same way the landing page was previewed first. Recommendation: yes. It is cheap, and it lets you try the five-second test yourself.

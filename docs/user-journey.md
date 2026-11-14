# Custos — the operator's journey (Phase 8b)

_The path a person new to Custos takes from a running stack to "I cut an agent off and can prove it", with no README open. It is the script for Phase 8b's stranger runs (`docs/build-plan.md`) and the target the CLI and dashboard work is built to. Design decisions are in ADR 0022; this file says what the person does and sees._

## Who and where they start

- **Who:** an operator: someone at a company who runs AI agents and is responsible for what they may do. They are not a Custos developer.
- **They have:** the stack running (`pnpm demo`), a terminal with the `custos` command, a browser, and a company login (demo: `alice`).
- **They do not have:** the README, an explanation, or anyone to ask.

## Rules every screen follows

1. **Every output ends with what to do next.** That holds for a success, a refusal and an error alike: one line, `Next: <exact command>`. The person never has to guess the next command.
2. **Words by default, JSON on request.** Commands print short sentences. `--json` gives the machine-readable form for scripts.
3. **Names first.** "billing-bot", "alice@company.com". DIDs and hashes are one click (dashboard) or `--json` (CLI) away.
4. **No flags on the main path.** Service addresses, file names and the identity issuer all have working defaults. A flag is needed only to do something unusual.
5. **Grey is fine, red is a problem.** A refusal is the product working. Red appears only when something is actually wrong (ADR 0022 §6).
6. **Commands take an agent's id or DID, never its name.** Names can repeat (ADR 0022 §2).

## The journey: eight moments

| #   | The person wants to…           | They do                                                                   | They see                                                                                                                                                                                                                                                              | Built in                   |
| --- | ------------------------------ | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| 1   | know where to start            | type `custos`                                                             | The lifecycle in order, one line each: sign in, register an agent, give it a tool, let it act, pass work to another agent, cut it off, check the record, check one agent. Each line has its command.                                                                  | CLI wording                |
| 2   | sign in                        | `custos login`                                                            | Their browser opens the company login. The terminal then shows: "Signed in as alice@company.com until 18:40. Next: `custos register --name <name>`".                                                                                                                  | exists, plus the Next line |
| 3   | add an agent                   | `custos register --name billing-bot`                                      | "Registered billing-bot (id `a1b2…`). Its private key is in `agent.key`; keep it secret. Next: `custos grant <tool> --to a1b2…`".                                                                                                                                     | names                      |
| 4   | let it use one tool            | `custos grant mock-database --to a1b2…`                                   | "billing-bot may now use mock-database. Next, as the agent: `custos use mock-database query`".                                                                                                                                                                        | grant by id                |
| 5   | see it work, and see a refusal | `custos use mock-database query`, then `custos use stripe list-customers` | The query result. Then: "Refused: billing-bot has not been given stripe. This is Custos working. To allow it: `custos grant stripe --to a1b2…`".                                                                                                                      | refusal catalogue          |
| 6   | look at the dashboard          | open http://localhost:4005, sign in                                       | **Now:** "All clear", with a grey "1 refusal in the last hour (normal)". **Who can do what:** "billing-bot (by alice@company.com) → mock-database".                                                                                                                   | dashboard                  |
| 7   | cut it off                     | `custos revoke a1b2…`                                                     | "billing-bot is cut off from every tool. Next: `custos status a1b2…` to confirm". Within about a second the dashboard's Now view shows "Cut off: billing-bot, 5 s ago, by alice@company.com", in grey because it was intended.                                        | aliases, dashboard         |
| 8   | prove what happened            | `custos audit-log`, or the dashboard's **Proof** view                     | "Verified: 9 entries, none changed since they were sealed." Then one line per event: "alice@company.com gave billing-bot mock-database · billing-bot queried mock-database: allowed · billing-bot asked for stripe: refused · alice@company.com cut off billing-bot". | audit wording, dashboard   |

**Delegation (optional ninth moment).** Register `helper-bot`, then run `custos delegate mock-database query --to <helper id>`. The output is "helper-bot may now query mock-database for billing-bot. Next, as helper-bot: `custos use mock-database query --delegation delegation.json`". On the dashboard and in the audit log the chain reads **alice@company.com → billing-bot → helper-bot**.

**Checking one agent.** `custos status a1b2…` prints:

- the agent's name and who registered it;
- what it may do: tools, and who granted each;
- whether it is cut off, when and by whom;
- its last five actions, each allowed or refused.

## Friction on today's path, and what removes it

| Today                                                                    | Why it is hard                                                          | Change                                                                                                                                                   | Needs                              |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `register` prints a JSON blob and says to "note the `id`".               | The person has to hunt for the id.                                      | Plain sentence with the id and the Next line. `--json` keeps the old output.                                                                             | in ADR 0022 §7 (wording)           |
| `grant <tool> --credential agent.json`                                   | The operator has to hold the agent's credential file to give it a tool. | `grant <tool> --to <agent id or DID>`. The old `--credential` form keeps working.                                                                        | **your OK** (new)                  |
| `use … --credential agent.json` on every call                            | A flag on the main path.                                                | `register` also saves the credential to `agent.json` by default, and `use` reads `agent.json` and `agent.key` by default. It never overwrites, as today. | **your OK** (new)                  |
| `deprovision` takes only the id; `delegate --to` takes only a DID        | Two different ways to name the same agent.                              | `revoke`, `status`, `grant --to` and `delegate --to` all take either the id or the DID.                                                                  | **your OK** (new)                  |
| Refusals print a code (`denied: POLICY_DENIED`).                         | The code means nothing to a newcomer.                                   | Meaning plus Next line, from the catalogue.                                                                                                              | in ADR 0022 §6                     |
| The operator key is pasted from `custos-admin dev-keys` output.          | A secret copied between terminals.                                      | `custos login` is the main path. The pasted key remains for scripts.                                                                                     | in ADR 0022 (Keycloak in the demo) |
| The first `custos audit-log` after `pnpm demo` stops with `KEY_CHANGED`. | It looks like an error, but it is the safety check doing its job.       | Plain message: "First time checking this record. Its seal key is X. If `pnpm demo` printed the same key, run: `custos audit-log --accept-key X`."        | in ADR 0022 §6                     |
| The `custos` command needs an alias set by hand.                         | A step before the journey even starts.                                  | The `pnpm demo` banner prints the exact line to make the `custos` command work, for bash and for PowerShell.                                             | **your OK** (new)                  |

The changes marked **your OK** are not in ADR 0022 as accepted. Once agreed, they are added to it, because they change command arguments and defaults.

## What a stranger run records

For each moment above, record:

- whether they got through it without help;
- how long it took;
- where they stopped, and what they said at that point.

Phase 8b is done when moments 6, 7 and 8 and the delegation chain pass for someone who has never seen Custos (`docs/build-plan.md`, DONE). Each run is written up as `docs/stranger-runs/<date>.md`.

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

| #   | The person wants to…           | They do                                                                   | They see                                                                                                                                                                                                                                                              | Built in                           |
| --- | ------------------------------ | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| 1   | know where to start            | type `custos`                                                             | The lifecycle in order, one line each: sign in, register an agent, give it a tool, let it act, pass work to another agent, cut it off, check the record, check one agent. Each line has its command.                                                                  | CLI wording                        |
| 2   | sign in                        | `custos login`                                                            | Their browser opens the company login. The terminal then shows: "Signed in as alice@company.com until 18:40. Next: `custos register --name <name>`".                                                                                                                  | exists, plus the Next line         |
| 3   | add an agent                   | `custos register --name billing-bot`                                      | "Registered billing-bot (id `a1b2…`). Its private key is in `agent.key`; keep it secret. Next: `custos grant <tool> --to a1b2…`".                                                                                                                                     | names                              |
| 4   | let it use one tool            | `custos grant mock-database --to a1b2…`                                   | "billing-bot may now use mock-database. Next, as the agent: `custos use mock-database query`".                                                                                                                                                                        | grant by id                        |
| 5   | see it work, and see a refusal | `custos use mock-database query`, then `custos use stripe list-customers` | The query result. Then: "Refused: billing-bot has not been given stripe. This is Custos working. To allow it: `custos grant stripe --to a1b2…`".                                                                                                                      | refusal catalogue                  |
| 6   | look at the dashboard          | open http://localhost:4005, sign in                                       | **Now:** "All clear", with a grey "1 refusal in the last hour (normal)". **Who can do what:** "billing-bot (by alice@company.com) → mock-database".                                                                                                                   | dashboard                          |
| 7   | cut it off                     | `custos revoke a1b2…`                                                     | "billing-bot is cut off from every tool. Next: `custos status a1b2…` to confirm". Within about a second the dashboard's Now view shows "Cut off: billing-bot, 5 s ago, by alice@company.com", in grey because it was intended.                                        | aliases, status (built), dashboard |
| 8   | prove what happened            | `custos audit-log`, or the dashboard's **Proof** view                     | "Verified: 9 entries, none changed since they were sealed." Then one line per event: "alice@company.com gave billing-bot mock-database · billing-bot queried mock-database: allowed · billing-bot asked for stripe: refused · alice@company.com cut off billing-bot". | audit wording, dashboard           |

**Delegation (optional ninth moment).** Register `helper-bot`, then run `custos delegate mock-database query --to <helper id>`. The output is "helper-bot may now query mock-database for billing-bot. Next, as helper-bot: `custos use mock-database query --delegation delegation.json`". On the dashboard and in the audit log the chain reads **alice@company.com → billing-bot → helper-bot**.

**Checking one agent (built in step 5b, `feat/custos-status`).** `custos status a1b2…` prints:

- the agent's name and who registered it;
- what it may do: tools, and who granted each;
- whether it is cut off, when and by whom;
- its last five actions, each allowed or refused, from the audit log checked as `custos audit-log` checks it.

Built as described, with these details: `revoke` now prints `Next: custos status <id>   (to confirm)`, and today it still says "Agent <id> is cut off", without the name. "By whom" for a cut-off comes from the checked audit log's revoke entry, because the revocation list does not record it. A part that cannot be read says "could not check" and the command exits 1. A tampered audit log is shown as an alarm, with no entries.

## On the dashboard, step by step (founder reviewed 2026-11-27)

Moments 6 to 8 in detail. The screens and their wording are in `docs/dashboard-plan.md`; this is the order a person meets them in, and what the dashboard's server must supply for each (the list the dashboard back end is built to).

**The main path**

| #   | The person does                                                 | They see                                                                                                                                                       | The server must                                                                                         |
| --- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 1   | opens http://localhost:4005                                     | Only "Sign in with your company account to see your agents." and a button. No data, no address boxes.                                                          | serve the page with no data in it; answer `401` on every `/api/*` until signed in                       |
| 2   | signs in with the company login (`alice`)                       | The same login as `custos login`; they land on **Now**, with "alice@company.com · Sign out" in the header.                                                     | run the sign-in with the one-time code (step 6); keep the read-only key in memory, behind a cookie      |
| 3   | (no agents yet)                                                 | The first-visit checklist: four commands to copy, a faded panel labelled EXAMPLE, and a line pointing to the SDK for registering from code.                    | say, for each of the four steps, whether it has happened: an agent, a grant, an allowed call, a cut-off |
| 4   | runs `custos register --name billing-bot`                       | Within about 2 s step 1 ticks, the checklist shrinks to a strip, and Now shows "✓ All clear", with "none" and "nothing refused" in words.                      | update Now about every 2 s: each service's health, and when the revocation list was last checked        |
| 5   | runs `custos grant mock-database --to …`, opens Who can do what | "billing-bot · alice@company.com · mock-database, given by alice@company.com". Clicking the name opens what `custos status` shows.                             | read agents with names and grants, about every 10 s                                                     |
| 6   | the agent queries, then asks for stripe                         | Still "All clear", plus a grey "Refused in the last hour: 1" with "billing-bot asked for stripe: not given this tool". Clicking it opens Proof.                | refusals of the last hour from the audit log, as sentences                                              |
| 7   | runs `custos revoke …`                                          | Within about a second: "All clear · billing-bot was cut off 5 s ago by alice@company.com" in grey, and the same row under "Cut off recently", marked for 10 s. | cut-offs of the last 24 h with who, when and why; "who" from the checked audit log                      |
| 8   | opens Proof, filters to billing-bot                             | "✓ Verified, 9 entries, none changed since they were sealed", then one sentence per event, newest first.                                                       | check the whole audit log with the same code as `custos audit-log`, about every 15 s; pin the seal key  |
| 9   | clicks the cut-off entry                                        | Its raw record, hash and signature check.                                                                                                                      | keep each entry's hash and raw record, not only its sentence                                            |
| 10  | delegates to helper-bot, which makes a call                     | "helper-bot · alice@company.com → billing-bot · mock-database: query", and the same chain in Proof.                                                            | delegation chains from the checked audit log                                                            |

**When something goes wrong**

| #   | What happened                           | They see                                                                                                                                                                   | The server must                                                                       |
| --- | --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| A   | sign-in failed or its link was used     | The reason in words and "Try again".                                                                                                                                       | turn `INVALID_LOGIN_CODE` and `RETURN_URL_NOT_ALLOWED` into words                     |
| B   | the group has no read scope             | "Your group cannot see anything here. Ask whoever runs Custos to add your group."                                                                                          | know the session key's scopes                                                         |
| C   | the group may see some views            | Grey "Your group cannot see grants." on that view; Now never says "All clear" over a part it could not see.                                                                | keep allowed, refused and failed apart, per view                                      |
| D   | a service stops answering               | A red strip naming it, a red headline with the next step, and the last good data greyed "as of 14:05".                                                                     | health per service, and the time of each part's last good answer                      |
| E   | the revocation list is out of date      | Red: "Revocation list last checked 11 min ago. Cut-offs may not reach the vault."                                                                                          | the list's freshness against its allowed age                                          |
| F   | the audit log was changed               | Red "✗ Tampered", which entry, and what to do; no entries shown.                                                                                                           | the check's failure in words                                                          |
| G   | the seal key changed                    | "Needs a person", the new key and the `--accept-key` command; never verified until a person accepts it.                                                                    | remember the first seal key; how a person accepts one is decided in the back-end step |
| H   | someone sends forged or replayed passes | Grey "12 forged or broken passes" within the last hour's refusals (plus "since the vault started at 14:01" if it restarted within the hour); no agent name, no proof link. | read the vault's in-memory count for the last hour (ADR 0022 §6)                      |
| I   | the sign-in runs out                    | "Your sign-in ran out. Sign in again." The data is cleared from the page.                                                                                                  | a `401` ends the page's data at once                                                  |
| J   | the dashboard restarts                  | Everyone signs in again; Proof checks the whole log afresh.                                                                                                                | keep nothing about sessions or keys on disk                                           |

The dashboard stays read-only: registering, granting and cutting off happen in the terminal or from code with the SDK (founder, 2026-11-27).

## Friction on today's path, and what removes it

| Today                                                                    | Why it is hard                                                          | Change                                                                                                                                                   | Needs                              |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `register` prints a JSON blob and says to "note the `id`".               | The person has to hunt for the id.                                      | Plain sentence with the id and the Next line. `--json` keeps the old output.                                                                             | in ADR 0022 §7 (wording)           |
| `grant <tool> --credential agent.json`                                   | The operator has to hold the agent's credential file to give it a tool. | `grant <tool> --to <agent id or DID>`. The old `--credential` form keeps working.                                                                        | built, PR #135                     |
| `use … --credential agent.json` on every call                            | A flag on the main path.                                                | `register` also saves the credential to `agent.json` by default, and `use` reads `agent.json` and `agent.key` by default. It never overwrites, as today. | built, PR #135                     |
| `deprovision` takes only the id; `delegate --to` takes only a DID        | Two different ways to name the same agent.                              | `revoke`, `status`, `grant --to` and `delegate --to` all take either the id or the DID.                                                                  | built, PR #135                     |
| Refusals print a code (`denied: POLICY_DENIED`).                         | The code means nothing to a newcomer.                                   | Meaning plus Next line, from the catalogue.                                                                                                              | in ADR 0022 §6                     |
| The operator key is pasted from `custos-admin dev-keys` output.          | A secret copied between terminals.                                      | `custos login` is the main path. The pasted key remains for scripts.                                                                                     | in ADR 0022 (Keycloak in the demo) |
| The first `custos audit-log` after `pnpm demo` stops with `KEY_CHANGED`. | It looks like an error, but it is the safety check doing its job.       | Plain message: "First time checking this record. Its seal key is X. If `pnpm demo` printed the same key, run: `custos audit-log --accept-key X`."        | in ADR 0022 §6                     |
| The `custos` command needs an alias set by hand.                         | A step before the journey even starts.                                  | The `pnpm demo` banner prints the exact line to make the `custos` command work, for bash and for PowerShell.                                             | built, PR #135                     |

The four changes marked built were agreed by the founder on 2026-11-15 and are recorded in ADR 0022 §7. `register --name` is built (moment 3); other commands show the name once identity's `GET /agents` lands with the read scopes. `custos status` is built (step 5b) and shows the name; `revoke`, `grant` and `use` still show ids.

## What a stranger run records

For each moment above, record:

- whether they got through it without help;
- how long it took;
- where they stopped, and what they said at that point.

Phase 8b is done when moments 6, 7 and 8 and the delegation chain pass for someone who has never seen Custos (`docs/build-plan.md`, DONE). Each run is written up as `docs/stranger-runs/<date>.md`.

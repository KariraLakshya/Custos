/**
 * The one catalogue of refusal reasons (ADR 0022 §6): for every code a
 * Custos service can answer a person with, what it means in plain words,
 * what to do next, and whether it is the product working (`normal`) or a
 * real problem (`alarm`).
 *
 * Every severity is written out; there is no default, so a new code cannot
 * turn the dashboard red by accident. Each service checks its error unions
 * against this catalogue at compile time (`refusal-catalogue.test.ts`), so a
 * code without an entry fails `pnpm typecheck`.
 *
 * `nextStep` may hold `<tool>` and `<agent>` for the caller to fill in.
 */
export type RefusalSeverity = "normal" | "alarm";

export interface RefusalEntry {
  readonly meaning: string;
  readonly nextStep: string;
  readonly severity: RefusalSeverity;
}

const WORKING = "Nothing to fix: this is Custos working.";

const entry = (
  severity: RefusalSeverity,
  meaning: string,
  nextStep: string = WORKING,
): RefusalEntry => ({ meaning, nextStep, severity });

/** Shown for a code this version of Custos does not know. */
export const UNKNOWN_REFUSAL: RefusalEntry = entry(
  "normal",
  "Custos refused this for a reason this version does not recognise.",
  "Update the custos CLI, or run again with --json and look up the code.",
);

export const REFUSALS = {
  // --- control plane (ADR 0008) ---
  UNKNOWN: UNKNOWN_REFUSAL,
  UNAUTHORIZED: entry(
    "normal",
    "You are not signed in, your sign-in has expired, or your group may not do this.",
    "Sign in with: custos login",
  ),
  UNAVAILABLE: entry(
    "alarm",
    "Custos could not decide safely because information it needs is missing or too old, so it refused.",
    "Check that every Custos service is running, then try again.",
  ),
  INVALID_INPUT: entry(
    "normal",
    "The request was not in the shape Custos expects.",
    "Check the command's arguments with: custos help <command>",
  ),

  // --- vault: asking for a token (`custos use`, first half) ---
  POLICY_DENIED: entry(
    "normal",
    "This agent has not been given this tool.",
    "To allow it, an operator runs: custos grant <tool> --credential <agent's credential file>",
  ),
  AGENT_REVOKED: entry(
    "normal",
    "This agent, or an agent it is acting for, has been cut off from every tool.",
    "A revoked agent cannot be restored. Register a new one with: custos register",
  ),
  UNKNOWN_TOOL: entry(
    "normal",
    "Custos has no tool by that name.",
    "Check the tool's name, or ask whoever runs Custos to connect the tool.",
  ),
  INVALID_AGENT_CREDENTIAL: entry(
    "normal",
    "The agent's identity credential was not accepted.",
    "Check that --credential points at the file `custos register` wrote for this agent.",
  ),
  INVALID_PROOF_OF_POSSESSION: entry(
    "normal",
    "The request did not prove it came from the agent that owns this credential.",
    "Check that --key points at this agent's private key file (agent.key).",
  ),
  DELEGATION_DENIED: entry(
    "normal",
    "The permission another agent passed on does not allow this.",
    "Ask the agent that passed it on for a new one: custos delegate <tool> <actions...> --to <agent>",
  ),
  SIGNING_FAILED: entry(
    "alarm",
    "A Custos service could not sign with its key, so it refused.",
    "Check the service's log and its key (KMS) configuration.",
  ),

  // --- vault: using the token (`custos use`, second half) ---
  INVALID_TOKEN: entry(
    "normal",
    "The short-lived token for this call was not accepted. Tokens last about a minute.",
    "Run the command again to get a new token.",
  ),
  ACTION_MISMATCH: entry(
    "normal",
    "The token was issued for a different action than the one asked for.",
    "Run the command again with the action you want.",
  ),
  REVOCATION_STATE_STALE: entry(
    "alarm",
    "The vault's list of cut-off agents is out of date, so it is refusing every call until it catches up.",
    "Check that the revocation service is running; the vault catches up within seconds once it is.",
  ),
  REVOCATION_STATE_UNKNOWN_AGENT: entry(
    "normal",
    "The vault has not checked this agent recently, so it refused this one call.",
    "Run the command again; it asks for a new token, which checks the agent.",
  ),
  UNKNOWN_ACTION: entry(
    "normal",
    "This tool has no action by that name.",
    "Check the action's name for this tool.",
  ),
  UPSTREAM_ERROR: entry(
    "normal",
    "Custos allowed the call, but the tool itself answered with an error.",
    "Check the tool is working and that the credential stored for it is still valid.",
  ),

  // --- identity: registering an agent (`custos register`) ---
  INVALID_PUBLIC_KEY: entry(
    "normal",
    "The agent's public key was not a valid key.",
    "Run custos register again; it makes a new key.",
  ),
  INVALID_REGISTRATION_PROOF: entry(
    "normal",
    "The registration did not prove it holds the agent's private key.",
    "Run custos register again; check this machine's clock is correct.",
  ),
  KEY_ALREADY_REGISTERED: entry(
    "normal",
    "An agent with this key is already registered.",
    "Run custos register again; it makes a new key.",
  ),
  STATUS_ALLOCATION_FAILED: entry(
    "alarm",
    "The identity service could not reach the revocation service, so it would not register an agent it could not later cut off.",
    "Check that the revocation service is running, then register again.",
  ),

  INVALID_AGENT_ID: entry(
    "normal",
    "That is not an agent id.",
    "Check the id: it is in the output of custos register.",
  ),
  AGENT_NOT_FOUND: entry(
    "normal",
    "No agent with that id is registered.",
    "Check the id: it is in the output of custos register.",
  ),

  // --- identity: signing in (`custos login`) ---
  SSO_BUSY: entry(
    "normal",
    "Too many sign-ins are in progress.",
    "Wait a minute, then run: custos login",
  ),
  UNKNOWN_LOGIN: entry(
    "normal",
    "This sign-in has expired or was never started.",
    "Start again with: custos login",
  ),
  TOKEN_REJECTED: entry(
    "normal",
    "The company login's answer was not accepted.",
    "Start again with: custos login",
  ),
  NO_MAPPED_GROUP: entry(
    "normal",
    "You signed in, but none of your company groups is allowed to operate Custos.",
    "Ask whoever runs Custos to add your group (SSO_GROUP_SCOPES).",
  ),
  PROVIDER_ERROR: entry(
    "alarm",
    "The company login service could not be reached or answered with an error.",
    "Check that the company login is running, then run: custos login",
  ),

  // --- revocation: cutting an agent off (`custos revoke`) ---
  UNKNOWN_AGENT: entry(
    "normal",
    "No agent with that id is registered.",
    "Check the id: it is in the output of custos register.",
  ),
  ALLOCATION_FAILED: entry(
    "alarm",
    "The revocation service could not reserve a place for the agent in its list.",
    "Check the revocation service's log and its database.",
  ),
  PUBLISHED_STATE_UNKNOWN: entry(
    "alarm",
    "The revocation service has not yet confirmed its published list, so it will not answer.",
    "Wait a few seconds and try again; if it lasts, check the revocation service's log.",
  ),
} as const satisfies Record<string, RefusalEntry>;

export type RefusalCode = keyof typeof REFUSALS;

/**
 * Finer reasons under a code, where the reason changes the meaning or the
 * fix. A reason with no entry falls back to its code's entry.
 */
export const REFUSAL_REASONS = {
  DELEGATION_DENIED: {
    NOT_COVERED: entry(
      "normal",
      "The permission passed on does not include this tool or action.",
      "Ask the agent that passed it on to include it: custos delegate <tool> <actions...> --to <agent>",
    ),
    WIDENED: entry(
      "normal",
      "A hand-off in the chain passes on more than its own agent was given.",
      "Make the delegation again, passing on only what the delegating agent holds.",
    ),
    EXPIRED: entry(
      "normal",
      "The permission passed on has run out.",
      "Ask the agent that passed it on for a new one: custos delegate <tool> <actions...> --to <agent>",
    ),
    NOT_YET_VALID: entry(
      "normal",
      "The permission passed on is not valid yet.",
      "Check the clocks on both machines, then try again.",
    ),
    CHAIN_ENDS_NOW: entry(
      "normal",
      "The permission passed on runs out this second.",
      "Ask the agent that passed it on for a new one: custos delegate <tool> <actions...> --to <agent>",
    ),
    NO_ROOT_GRANT: entry(
      "normal",
      "The first agent in the chain was not given this tool by an operator.",
      "An operator grants it first: custos grant <tool> --credential <first agent's credential file>",
    ),
    TOO_MANY_LINKS: entry(
      "normal",
      "The permission has been passed on more times than Custos allows.",
      "Delegate from an agent nearer the start of the chain.",
    ),
    TOO_LARGE: entry(
      "normal",
      "The delegation file is larger than Custos accepts.",
      "Delegate from an agent nearer the start of the chain.",
    ),
    WRONG_HOLDER: entry(
      "normal",
      "This delegation was made out to a different agent.",
      "Use the delegation with the agent it was given to, or make a new one with --to this agent.",
    ),
    BROKEN_LINK: entry(
      "normal",
      "The hand-offs in the delegation file do not follow on from each other.",
      "Make the delegation again with custos delegate; do not edit the file.",
    ),
    SIGNATURE_INVALID: entry(
      "normal",
      "A hand-off in the delegation was not signed by the agent it names, or was changed afterwards.",
      "Make the delegation again with custos delegate; do not edit the file.",
    ),
    CREDENTIAL_INVALID: entry(
      "normal",
      "An agent in the chain has an identity credential that was not accepted.",
      "Make the delegation again with each agent's own credential file.",
    ),
    MALFORMED_CHAIN: entry(
      "normal",
      "The delegation file is not in the shape Custos expects.",
      "Make the delegation again with custos delegate; do not edit the file.",
    ),
    WRONG_TYPE: entry(
      "normal",
      "The delegation file holds something that is not a hand-off.",
      "Make the delegation again with custos delegate; do not edit the file.",
    ),
    INVALID_LIMITS: entry(
      "alarm",
      "The vault's own delegation limits are set wrongly.",
      "Check the vault's DELEGATION_MAX_* settings.",
    ),
    DELEGATOR_STATUS_INVALID: entry(
      "normal",
      "An agent in the chain has a credential the vault cannot check for revocation.",
      "Make the delegation again with each agent's own credential file.",
    ),
  },
  INVALID_PROOF_OF_POSSESSION: {
    WRONG_AUDIENCE: entry(
      "normal",
      "The request was signed for a different vault address than the one it reached.",
      "Use the vault's own address exactly (for example localhost, not 127.0.0.1) in --vault-url.",
    ),
    STALE: entry(
      "normal",
      "The request's timestamp is too far from the vault's clock.",
      "Check this machine's clock is correct, then try again.",
    ),
    WRONG_REQUEST: entry(
      "normal",
      "The request was signed for a different tool or action than the one asked for.",
      "Run the command again.",
    ),
    SIGNATURE_INVALID: entry(
      "normal",
      "The request was not signed with this agent's private key.",
      "Check that --key points at this agent's private key file (agent.key).",
    ),
    MALFORMED_PROOF: entry(
      "normal",
      "The proof sent with the request is not in the shape Custos expects.",
      "Update the custos CLI or SDK, then try again.",
    ),
    WRONG_TYPE: entry(
      "normal",
      "The proof sent with the request is of the wrong kind.",
      "Update the custos CLI or SDK, then try again.",
    ),
    REPLAYED: entry(
      "normal",
      "This exact request was already used once. Each request may be used only once.",
      "Run the command again; it signs a new request.",
    ),
    REPLAY_CACHE_FULL: entry(
      "alarm",
      "The vault is receiving more requests than it can safely track, so it refused.",
      "Wait a minute and try again; if it lasts, check what is flooding the vault.",
    ),
  },
  INVALID_AGENT_CREDENTIAL: {
    UNTRUSTED_ISSUER: entry(
      "normal",
      "The agent's credential was issued by an identity service this vault does not trust.",
      "Register the agent with this company's identity service: custos register",
    ),
    SIGNATURE_INVALID: entry(
      "normal",
      "The agent's credential was not signed by the identity service, or was changed afterwards.",
      "Use the credential file exactly as `custos register` wrote it; do not edit it.",
    ),
    MALFORMED_CREDENTIAL: entry(
      "normal",
      "The credential file is not in the shape Custos expects.",
      "Use the credential file exactly as `custos register` wrote it; do not edit it.",
    ),
  },
} as const satisfies { readonly [C in RefusalCode]?: Record<string, RefusalEntry> };

/**
 * The entry for a code a service answered with, and its finer reason when
 * it sent one. `code` and `reason` come off the wire, so they are treated as
 * untrusted: anything unknown, including a name inherited from
 * `Object.prototype`, gets `UNKNOWN_REFUSAL`.
 */
export function refusalFor(code: unknown, reason?: unknown): RefusalEntry {
  if (typeof code !== "string" || !Object.hasOwn(REFUSALS, code)) return UNKNOWN_REFUSAL;
  const reasons: Readonly<Record<string, Readonly<Record<string, RefusalEntry>>>> = REFUSAL_REASONS;
  const underCode = Object.hasOwn(reasons, code) ? reasons[code] : undefined;
  if (underCode !== undefined && typeof reason === "string" && Object.hasOwn(underCode, reason)) {
    return underCode[reason] ?? UNKNOWN_REFUSAL;
  }
  return REFUSALS[code as RefusalCode];
}

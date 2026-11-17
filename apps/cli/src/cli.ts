import { open, readFile, rm, writeFile } from "node:fs/promises";
import { AGENT_NAME_MAX_LENGTH, agentNameSchema, refusalFor } from "@custos/contracts";
import {
  createCustos,
  CustosError,
  type CallDenied,
  type Custos,
  type CustosConfig,
  type Delegation,
} from "@custos/sdk";
import { Command } from "commander";
import { openSealStore } from "@custos/audit-client";
import { defaultSealFile, pullAuditLog, type AuditLogError } from "./audit-log.js";
import { explainAuditFailure } from "./audit-words.js";
import { restrictToOwner } from "./key-file.js";
import { defaultOperatorKeyFile, findOperatorKey, login } from "./login.js";
import { loadCredentialFile, verifyCredentialIndependently } from "./verify.js";

interface AuditLogOptions {
  readonly auditUrl: string;
  readonly sealFile: string;
  readonly acceptKey?: string[];
  readonly identityIssuer: string;
}

/** The seal key a failed check is waiting on a person to accept, if that is why it failed. */
function untrustedKeyOf(error: AuditLogError): string | undefined {
  if (error.code === "KEY_CHANGED") return error.current;
  if (error.code === "SEAL_INVALID" && error.error.code === "UNTRUSTED_KEY") return error.error.key;
  return undefined;
}

/** What to do about a seal key this machine has not trusted (ADR 0017, key rotation). */
function acceptKeyHelp(key: string): string {
  return [
    `the audit log is sealed with a key this machine has not trusted: ${key}`,
    "Check it with whoever runs the audit service (`pnpm demo` prints its seal key at start).",
    "Do not check it against the service's own DID document: the service controls that.",
    `If it matches, run again with: --accept-key ${key}`,
    "",
  ].join("\n");
}

const DEFAULT_URLS: CustosConfig = {
  identityUrl: "http://localhost:4001",
  vaultUrl: "http://localhost:4002",
  revocationUrl: "http://localhost:4003",
};

/**
 * Each command talks to one service and takes only that service's URL; the
 * SDK wants all three but only contacts the one a call needs.
 */
function custos(urls: Partial<CustosConfig>): Custos {
  return createCustos({ ...DEFAULT_URLS, ...urls });
}

/**
 * For operator commands (`register`, `grant`, `revoke`). The key comes
 * from the environment only, never a flag, so it stays out of shell history
 * and process listings (ADR 0008).
 */
async function operatorCustos(urls: Partial<CustosConfig>): Promise<Custos> {
  const operatorKey = await findOperatorKey();
  if (!operatorKey) {
    throw new CliError(
      "you are not signed in as an operator",
      "custos login   (scripts: set CUSTOS_OPERATOR_KEY; create a key with: pnpm custos-admin dev-keys)",
    );
  }
  return createCustos({ ...DEFAULT_URLS, ...urls, operatorKey });
}

/** A mistake the CLI catches itself, with the step that fixes it (ADR 0022 §6). */
class CliError extends Error {
  constructor(
    message: string,
    readonly next: string,
  ) {
    super(message);
  }
}

function wholeNumber(flag: string, value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new CliError(
      `${flag} must be a whole number, got ${value}`,
      `use, for example: ${flag} 600`,
    );
  }
  return Number(value);
}

/** Reads an agent key file as `register` writes it: 64 hex characters. */
async function loadAgentKey(path: string): Promise<string> {
  let key: string;
  try {
    key = (await readFile(path, "utf8")).trim();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    throw new CliError(
      `no agent key at ${path}`,
      "run this where `custos register` wrote agent.key, or pass --key <path>",
    );
  }
  if (!/^[0-9a-f]{64}$/i.test(key)) {
    throw new CliError(
      `not an agent key: ${path} (expected 64 hex characters)`,
      "pass the key file `custos register` wrote for this agent: --key <path>",
    );
  }
  return key;
}

/** Reads the agent's credential, `agent.json` unless told otherwise. */
async function loadAgentCredential(path: string): ReturnType<typeof loadCredentialFile> {
  try {
    return await loadCredentialFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    throw new CliError(
      `no agent credential at ${path}`,
      "run this where `custos register` wrote agent.json, or pass --credential <path>",
    );
  }
}

const DEFAULT_IDENTITY_ISSUER = "did:web:localhost%3A4001";
const AGENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const AGENT_DID = /^did:web:[A-Za-z0-9.%:_-]+:agents:([0-9a-f-]{36})$/i;

/**
 * An agent named by its id or its DID (ADR 0022 §7); never by its name,
 * which can repeat. Custos agent DIDs are `<issuer DID>:agents:<id>`, so an
 * id becomes a DID under `issuerDid`, and a DID carries its id.
 */
function agentRef(ref: string, issuerDid: string): { readonly id: string; readonly did: string } {
  if (AGENT_ID.test(ref)) return { id: ref, did: `${issuerDid}:agents:${ref}` };
  const id = AGENT_DID.exec(ref)?.[1];
  if (id !== undefined && AGENT_ID.test(id)) return { id, did: ref };
  throw new CliError(
    "that is not an agent id or DID",
    "use the id `custos register` printed (it looks like 3f2b8c1e-…), or the agent's DID",
  );
}

// Matches the vault's own bound on a presented chain (ADR 0020).
const MAX_DELEGATION_ENTRIES = 16;

/**
 * Reads a delegation file as `delegate` writes it. Untrusted input: anything
 * that is not 1 to 16 hand-off strings and as many credential objects is
 * refused here, before it is sent anywhere.
 */
async function loadDelegationFile(path: string): Promise<Delegation> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`no delegation file at ${path}`);
    }
    throw new Error(`not a delegation file: ${path} is not JSON`);
  }
  const { handOffs, credentials } = (parsed ?? {}) as Record<string, unknown>;
  const within = (list: unknown): list is unknown[] =>
    Array.isArray(list) && list.length >= 1 && list.length <= MAX_DELEGATION_ENTRIES;
  if (
    !within(handOffs) ||
    !within(credentials) ||
    !handOffs.every((h) => typeof h === "string" && h.length > 0) ||
    !credentials.every(
      (c) =>
        typeof c === "object" &&
        c !== null &&
        typeof (c as { issuer?: unknown }).issuer === "string",
    )
  ) {
    throw new Error(
      `not a delegation file: ${path} needs 1 to ${MAX_DELEGATION_ENTRIES} hand-offs and credentials`,
    );
  }
  return { handOffs: handOffs as string[], credentials: credentials as Delegation["credentials"] };
}

/** The agent is the credential's subject; the issuer is the identity service (ADR 0007). */
function agentDidOf(credential: { readonly credentialSubject?: unknown }): string {
  const subject = credential.credentialSubject as { id?: unknown } | undefined;
  if (typeof subject?.id !== "string") {
    throw new Error("not a usable credential: no credentialSubject.id");
  }
  return subject.id;
}

// Codes and reasons come off the wire. Only this shape is printed as-is, so a
// service cannot write control characters to the terminal.
const CODE_SHAPE = /^[A-Z][A-Z0-9_]{0,63}$/;

/**
 * A refusal in words (ADR 0022 §6): what it means, what to do next, and the
 * code for scripts and searching. "Refused" is Custos working; "Problem" is
 * something actually wrong. `fill` supplies the `<tool>` and `<agent>` a next
 * step may name; both come from this command's own arguments and files.
 */
function explainRefusal(
  code: unknown,
  reason: unknown,
  fill: { readonly tool?: string; readonly agent?: string } = {},
): string {
  const entry = refusalFor(code, reason);
  const next = entry.nextStep
    .replaceAll("<tool>", fill.tool ?? "<tool>")
    .replaceAll("<agent>", fill.agent ?? "<agent id>");
  const shownCode = typeof code === "string" && CODE_SHAPE.test(code) ? code : "UNKNOWN";
  const shownReason = typeof reason === "string" && CODE_SHAPE.test(reason) ? ` (${reason})` : "";
  return [
    `${entry.severity === "alarm" ? "Problem" : "Refused"}: ${entry.meaning}`,
    `Next: ${next}`,
    `Code: ${shownCode}${shownReason}`,
    "",
  ].join("\n");
}

/** 401/403 are the vault's authorization decisions; anything else is a failure worth its detail. */
function describeRefusal(
  refusal: CallDenied,
  fill: { readonly tool: string; readonly agent?: string },
): string {
  const reason = (refusal.detail as { error?: { reason?: unknown } } | undefined)?.error?.reason;
  const explained = explainRefusal(refusal.code, reason, fill);
  if (refusal.status === 401 || refusal.status === 403) return explained;
  // JSON.stringify escapes control characters.
  return `${explained}Detail: HTTP ${refusal.status} ${JSON.stringify(refusal.detail)}\n`;
}

const LIFECYCLE = `Custos: a trust layer for AI agents. The steps, in order:

  1. Sign in                      custos login
  2. Register an agent            custos register
  3. Give it a tool               custos grant <tool> --to <agent id>
  4. Let it act                   custos use <tool> <action>
  5. Pass work to another agent   custos delegate <tool> <actions...> --to <other agent id>
  6. Cut it off                   custos revoke <agent id>
  7. Check the record             custos audit-log

Next: custos login
Details of any step: custos help <command>
`;

export function createCli(): Command {
  const program = new Command()
    .name("custos")
    .description("Custos — a trust layer for AI agents")
    .version("0.0.0")
    // `custos` alone: the lifecycle in order, not commander's alphabetical help.
    .action(() => {
      // A root action also receives a mistyped command: refuse it as before.
      const [unknown] = program.args;
      if (unknown !== undefined) {
        program.error(`error: unknown command '${unknown}'. Run custos to see the steps.`);
      }
      process.stdout.write(LIFECYCLE);
    });

  program
    .command("login")
    .description("Sign in as an operator with your company account (SSO)")
    .option("--identity-url <url>", "identity service base URL", "http://localhost:4001")
    .option(
      "--key-file <path>",
      "where to keep the session's operator key",
      defaultOperatorKeyFile(),
    )
    .option("--no-browser", "print the sign-in URL without opening a browser")
    .action(async (opts: { identityUrl: string; keyFile: string; browser: boolean }) => {
      const result = await login(opts, {
        out: (line) =>
          process.stdout.write(`${line}
`),
      });
      // The key itself is never printed.
      process.stdout.write(
        `signed in as ${result.name} until ${result.expiresAt}; operator key saved to ${opts.keyFile}
Next: custos register
`,
      );
    });

  program
    .command("register")
    .description("Register a new agent and issue its identity credential")
    .option("--identity-url <url>", "identity service base URL", "http://localhost:4001")
    .option(
      "--name <name>",
      "a name to show beside the agent; not unique, and commands still take its id",
    )
    .option(
      "--out <path>",
      "where to write the agent's credential (never overwrites an existing file)",
      "agent.json",
    )
    .option(
      "--key-out <path>",
      "where to write the agent's private key (never overwrites an existing file)",
      "agent.key",
    )
    .option("--json", "print the result as JSON")
    .action(
      async (opts: {
        identityUrl: string;
        name?: string;
        out: string;
        keyOut: string;
        json?: boolean;
      }) => {
        // Refused here, before any file or request, with the rule in words.
        if (opts.name !== undefined && !agentNameSchema.safeParse(opts.name).success) {
          throw new CliError(
            "that name cannot be used",
            `use 1 to ${AGENT_NAME_MAX_LENGTH} letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit, for example --name billing-bot`,
          );
        }
        // Before any file is claimed: a missing operator key leaves nothing behind.
        const operator = await operatorCustos({ identityUrl: opts.identityUrl });
        // Claim both files before registering: "wx" fails if one exists, so an
        // existing agent's key or credential is never overwritten. 0o600 keeps
        // the key owner-only (POSIX; Windows ignores the mode, so
        // restrictToOwner sets the ACL, before the key exists to be read).
        const claim = async (path: string, what: string, flag: string, mode?: number) => {
          try {
            return await open(path, "wx", mode);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
            throw new CliError(
              `refusing to overwrite existing ${what} ${path}`,
              `run this in an empty directory, or pass ${flag} <path> for the new agent`,
            );
          }
        };
        const keyFile = await claim(opts.keyOut, "key file", "--key-out", 0o600);
        let credentialFile;
        try {
          credentialFile = await claim(opts.out, "credential file", "--out");
        } catch (error) {
          await keyFile.close();
          await rm(opts.keyOut, { force: true });
          throw error;
        }
        try {
          await restrictToOwner(opts.keyOut);
          const { secretKey, ...agent } = await operator.register(
            opts.name === undefined ? {} : { name: opts.name },
          );
          await keyFile.writeFile(`${secretKey}\n`);
          await keyFile.close();
          await credentialFile.writeFile(JSON.stringify(agent.credential, null, 2));
          await credentialFile.close();
          // The name comes back off the wire: printed only if it passes the
          // same rule, so a service cannot write control characters to the terminal.
          const shownName = agentNameSchema.safeParse(agent.name);
          // The private key is never printed — stdout ends up in logs.
          process.stdout.write(
            opts.json
              ? `${JSON.stringify({ ...agent, keyFile: opts.keyOut, credentialFile: opts.out }, null, 2)}\n`
              : [
                  shownName.success
                    ? `Registered ${shownName.data} (id ${agent.id}).`
                    : `Registered agent ${agent.id}.`,
                  `Its credential is in ${opts.out} and its private key in ${opts.keyOut}. Keep the key secret.`,
                  `Next: custos grant <tool> --to ${agent.id}`,
                  "",
                ].join("\n"),
          );
        } catch (error) {
          // No agent was registered for these files: leave nothing behind.
          await keyFile.close();
          await credentialFile.close();
          await rm(opts.keyOut, { force: true });
          await rm(opts.out, { force: true });
          throw error;
        }
      },
    );

  program
    .command("verify")
    .argument("<credentialFile>", "path to a signed credential JSON file")
    .description("Independently verify an agent's identity credential")
    .action(async (credentialFile: string) => {
      const credential = await loadCredentialFile(credentialFile);
      const outcome = await verifyCredentialIndependently(credential);
      if (outcome.verified) {
        process.stdout.write("verified: credential is authentic\n");
        return;
      }
      process.stderr.write(`rejected: ${outcome.reason}\n`);
      process.exitCode = 1;
    });

  program
    .command("use")
    .description("Request a scoped vault token for a tool action and immediately call it")
    .argument("<tool>", "tool name, e.g. stripe")
    .argument("<action>", "action to invoke, e.g. list-customers")
    .option(
      "--credential <path>",
      "path to the agent's credential file (from `register`)",
      "agent.json",
    )
    .option(
      "--key <path>",
      "path to the agent's private key (from `register`); proves this is the agent",
      "agent.key",
    )
    .option("--vault-url <url>", "vault service base URL", "http://localhost:4002")
    .option("--input <json>", "JSON input for the action", "{}")
    .option(
      "--delegation <path>",
      "act on permission another agent passed to this one (from `custos delegate`)",
    )
    .action(
      async (
        tool: string,
        action: string,
        opts: {
          credential: string;
          key: string;
          vaultUrl: string;
          input: string;
          delegation?: string;
        },
      ) => {
        const credential = await loadAgentCredential(opts.credential);
        const secretKey = await loadAgentKey(opts.key);
        const delegation =
          opts.delegation === undefined ? undefined : await loadDelegationFile(opts.delegation);
        let input: unknown;
        try {
          input = JSON.parse(opts.input);
        } catch {
          throw new CliError(
            "--input is not JSON",
            `quote it for your shell, for example: --input '{"table":"customers"}'`,
          );
        }
        const outcome = await custos({ vaultUrl: opts.vaultUrl })
          .connect(
            { credential, secretKey },
            tool,
            delegation === undefined ? undefined : { delegation },
          )
          .call(action, input);
        if (!outcome.ok) {
          // The agent's own id, from its own credential file, for the next step.
          const subject = (credential.credentialSubject as { id?: unknown } | undefined)?.id;
          const agent = typeof subject === "string" ? AGENT_DID.exec(subject)?.[1] : undefined;
          process.stderr.write(
            describeRefusal(outcome.error, { tool, ...(agent === undefined ? {} : { agent }) }),
          );
          process.exitCode = 1;
          return;
        }
        process.stdout.write(`${JSON.stringify({ result: outcome.value }, null, 2)}\n`);
      },
    );

  program
    .command("delegate")
    .description(
      "Pass some of this agent's permission to another agent, signed with this agent's key; nothing is sent",
    )
    .argument("<tool>", "tool to pass on, e.g. mock-database")
    .argument("<actions...>", "actions on it the other agent may take, e.g. query")
    .requiredOption("--to <agent>", "the receiving agent's id or DID")
    .option(
      "--credential <path>",
      "path to this (delegating) agent's credential file (from `register`)",
      "agent.json",
    )
    .option("--key <path>", "path to this agent's private key (from `register`)", "agent.key")
    .option(
      "--identity-issuer <did>",
      "the identity service's DID; turns an agent id into its DID",
      DEFAULT_IDENTITY_ISSUER,
    )
    .option("--ttl <seconds>", "how long it lasts (default 600; never past what it extends)")
    .option("--depth <n>", "how many more times it may be passed on (default 0: not at all)")
    .option("--extending <path>", "a delegation this agent received and is passing on")
    .option(
      "--out <path>",
      "where to write it, for the other agent's `use --delegation` (never overwrites)",
      "delegation.json",
    )
    .action(
      async (
        tool: string,
        actions: string[],
        opts: {
          to: string;
          credential: string;
          key: string;
          ttl?: string;
          depth?: string;
          extending?: string;
          out: string;
          identityIssuer: string;
        },
      ) => {
        const to = agentRef(opts.to, opts.identityIssuer);
        const credential = await loadAgentCredential(opts.credential);
        const secretKey = await loadAgentKey(opts.key);
        const extending =
          opts.extending === undefined ? undefined : await loadDelegationFile(opts.extending);
        const delegation = custos({}).delegate(
          { did: agentDidOf(credential), credential, secretKey },
          {
            to: to.did,
            grants: [{ tool, actions }],
            ...(opts.ttl === undefined ? {} : { ttlSeconds: wholeNumber("--ttl", opts.ttl) }),
            ...(opts.depth === undefined ? {} : { depth: wholeNumber("--depth", opts.depth) }),
            ...(extending === undefined ? {} : { extending }),
          },
        );
        try {
          await writeFile(opts.out, `${JSON.stringify(delegation, null, 2)}\n`, { flag: "wx" });
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "EEXIST") {
            throw new CliError(
              `refusing to overwrite existing file ${opts.out}`,
              "pass --out <path> for the new delegation",
            );
          }
          throw error;
        }
        process.stdout.write(
          [
            `Agent ${to.id} may now ${actions.join(", ")} on ${tool} for this agent. Give it ${opts.out}.`,
            `Next, as that agent: custos use ${tool} ${actions[0] ?? "<action>"} --delegation ${opts.out}`,
            "",
          ].join("\n"),
        );
      },
    );

  program
    .command("grant")
    .description("Give an agent one tool; without this every call is refused")
    .argument("<tool>", "tool name, e.g. stripe")
    .option("--to <agent>", "the agent's id or DID")
    .option("--credential <path>", "or: the agent's credential file (the older way to name it)")
    .option(
      "--identity-issuer <did>",
      "the identity service's DID; turns an agent id into its DID",
      DEFAULT_IDENTITY_ISSUER,
    )
    .option("--vault-url <url>", "vault service base URL", "http://localhost:4002")
    .option("--json", "print the result as JSON")
    .action(
      async (
        tool: string,
        opts: {
          to?: string;
          credential?: string;
          identityIssuer: string;
          vaultUrl: string;
          json?: boolean;
        },
      ) => {
        // Never a default here: an operator says which agent gets the tool.
        if ((opts.to === undefined) === (opts.credential === undefined)) {
          throw new CliError(
            "say which agent gets the tool, one way only",
            `custos grant ${tool} --to <agent id>`,
          );
        }
        const operator = await operatorCustos({ vaultUrl: opts.vaultUrl });
        const did =
          opts.to !== undefined
            ? agentRef(opts.to, opts.identityIssuer).did
            : agentDidOf(await loadAgentCredential(opts.credential ?? ""));
        const result = await operator.grant({ did }, tool);
        process.stdout.write(
          opts.json
            ? `${JSON.stringify(result, null, 2)}\n`
            : [
                `Agent ${agentRef(did, opts.identityIssuer).id} may now use ${tool}.`,
                `Next, as the agent: custos use ${tool} <action>`,
                "",
              ].join("\n"),
        );
      },
    );

  program
    .command("audit-log")
    .description(
      "Pull and independently verify the sealed audit log (ADR 0017) for an agent (or every agent)",
    )
    .argument("[agent]", "show only this agent's entries: its id or DID")
    .option("--audit-url <url>", "audit service base URL", "http://localhost:4004")
    .option(
      "--seal-file <path>",
      "where the newest verified seal is remembered between checks",
      defaultSealFile(),
    )
    .option(
      "--accept-key <key>",
      "a seal key you have checked with the audit service's operator (after KEY_CHANGED or UNTRUSTED_KEY); repeat for several",
      // Repeatable rather than variadic, so an agent DID after it is not taken for a key.
      (key: string, previous: string[]) => [...previous, key],
      [] as string[],
    )
    .option(
      "--identity-issuer <did>",
      "the identity service's DID; delegation chains in the log are re-verified against it",
      DEFAULT_IDENTITY_ISSUER,
    )
    .action(async (agent: string | undefined, opts: AuditLogOptions) => {
      const agentDid = agent === undefined ? undefined : agentRef(agent, opts.identityIssuer).did;
      // The seal store's address holds a password, so it comes from the
      // environment only, never a flag (ADR 0017 part 2a). postgres:// or
      // s3://<bucket> (part 2b).
      const storeUrl = process.env.CUSTOS_AUDIT_SEAL_STORE_URL;
      const sealStore = storeUrl ? await openSealStore(storeUrl) : undefined;
      const result = await pullAuditLog({
        auditUrl: opts.auditUrl,
        sealFile: opts.sealFile,
        ...(agentDid === undefined ? {} : { agentDid }),
        ...(sealStore === undefined ? {} : { sealStore }),
        ...(opts.acceptKey === undefined ? {} : { acceptKeys: opts.acceptKey }),
        identityIssuerDid: opts.identityIssuer,
      }).finally(() => sealStore?.close());
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      if (!result.verified) {
        process.stderr.write(explainAuditFailure(result.error));
        const newKey = untrustedKeyOf(result.error);
        if (newKey !== undefined) process.stderr.write(acceptKeyHelp(newKey));
        process.exitCode = 1;
        return;
      }
      for (const delegation of result.delegations) {
        process.stderr.write(`#${delegation.seq} ${delegation.kind}: ${delegation.chain}
`);
      }
      if (!result.outsideSealsChecked) {
        process.stderr.write(
          "note: no outside seal store was checked (set CUSTOS_AUDIT_SEAL_STORE_URL); the newest entries are protected only by seals this machine remembered\n",
        );
      }
    });

  program
    .command("revoke")
    // The old name keeps working.
    .alias("deprovision")
    .description("Cut an agent off from every tool it can reach; this cannot be undone")
    .argument("<agent>", "the agent's id or DID")
    .option("--revocation-url <url>", "revocation service base URL", "http://localhost:4003")
    .option("--reason <text>", "why this agent is being cut off")
    .option("--json", "print the result as JSON")
    .action(
      async (agent: string, opts: { revocationUrl: string; reason?: string; json?: boolean }) => {
        // Only the id is sent; the issuer in a DID is not needed to find it.
        const { id } = agentRef(agent, DEFAULT_IDENTITY_ISSUER);
        const result = await (
          await operatorCustos({ revocationUrl: opts.revocationUrl })
        ).deprovision({ id }, opts.reason === undefined ? undefined : { reason: opts.reason });
        if (opts.json) {
          process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
          return;
        }
        const { delivered, failed } = result.broadcast;
        process.stdout.write(
          [
            result.alreadyRevoked
              ? `Agent ${result.agentId} was already cut off. Nothing changed.`
              : `Agent ${result.agentId} is cut off from every tool. This cannot be undone.`,
            `Vaults told now: ${delivered}.`,
            ...(failed.length === 0
              ? []
              : [
                  `Problem: ${failed.length} vault(s) could not be told now. They refuse the agent after their next sync, within seconds of being reachable.`,
                ]),
            "Next: custos audit-log   (the record shows the cut-off)",
            "",
          ].join("\n"),
        );
      },
    );

  return program;
}

/**
 * Runs the CLI for real: a failed command is reported on stderr with exit
 * code 1, not an unhandled rejection's stack trace. A service's refusal, or a
 * service that did not answer, is explained in words with a next step.
 */
export async function runCli(argv: readonly string[]): Promise<void> {
  try {
    await createCli().parseAsync(argv);
  } catch (error: unknown) {
    process.stderr.write(
      error instanceof CustosError
        ? explainRefusal(error.code, error.reason)
        : error instanceof CliError
          ? `error: ${error.message}\nNext: ${error.next}\n`
          : `error: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}

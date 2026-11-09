import { open, readFile, rm, writeFile } from "node:fs/promises";
import {
  createCustos,
  type CallDenied,
  type Custos,
  type CustosConfig,
  type Delegation,
} from "@custos/sdk";
import { Command } from "commander";
import { openSealStore } from "@custos/audit-client";
import { defaultSealFile, pullAuditLog, type AuditLogError } from "./audit-log.js";
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
 * For operator commands (`register`, `grant`, `deprovision`). The key comes
 * from the environment only, never a flag, so it stays out of shell history
 * and process listings (ADR 0008).
 */
async function operatorCustos(urls: Partial<CustosConfig>): Promise<Custos> {
  const operatorKey = await findOperatorKey();
  if (!operatorKey) {
    throw new Error(
      "sign in with `custos login`, or set CUSTOS_OPERATOR_KEY to an operator key (create one with: pnpm custos-admin dev-keys)",
    );
  }
  return createCustos({ ...DEFAULT_URLS, ...urls, operatorKey });
}

function wholeNumber(flag: string, value: string): number {
  if (!/^\d+$/.test(value)) throw new Error(`${flag} must be a whole number, got ${value}`);
  return Number(value);
}

/** Reads an agent key file as `register` writes it: 64 hex characters. */
async function loadAgentKey(path: string): Promise<string> {
  const key = (await readFile(path, "utf8")).trim();
  if (!/^[0-9a-f]{64}$/i.test(key)) {
    throw new Error(`not an agent key: ${path} (expected 64 hex characters)`);
  }
  return key;
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

/** 401/403 are the vault's authorization decisions; anything else is a failure worth its detail. */
function describeRefusal(refusal: CallDenied): string {
  if (refusal.status === 401 || refusal.status === 403) {
    // A delegation refusal says why (NOT_COVERED, NO_ROOT_GRANT, ...); the code alone does not.
    const reason = (refusal.detail as { error?: { reason?: unknown } } | undefined)?.error?.reason;
    return typeof reason === "string"
      ? `denied: ${refusal.code} (${reason})`
      : `denied: ${refusal.code}`;
  }
  return `failed: ${refusal.code} (HTTP ${refusal.status}) — ${JSON.stringify(refusal.detail)}`;
}

export function createCli(): Command {
  const program = new Command()
    .name("custos")
    .description("Custos — a trust layer for AI agents")
    .version("0.0.0");

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
`,
      );
    });

  program
    .command("register")
    .description("Register a new agent and issue its identity credential")
    .option("--identity-url <url>", "identity service base URL", "http://localhost:4001")
    .option("--out <path>", "write the issued credential to a file")
    .option(
      "--key-out <path>",
      "where to write the agent's private key (never overwrites an existing file)",
      "agent.key",
    )
    .action(async (opts: { identityUrl: string; out?: string; keyOut: string }) => {
      // Before the key file is claimed: a missing operator key leaves nothing behind.
      const operator = await operatorCustos({ identityUrl: opts.identityUrl });
      // Claim the key file before registering: "wx" fails if it exists, so an
      // existing agent's key is never overwritten, and 0o600 keeps it
      // owner-only (POSIX; Windows ignores the mode, so restrictToOwner sets
      // the ACL, before the key exists to be read).
      let keyFile;
      try {
        keyFile = await open(opts.keyOut, "wx", 0o600);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          throw new Error(`refusing to overwrite existing key file ${opts.keyOut}`);
        }
        throw error;
      }
      try {
        await restrictToOwner(opts.keyOut);
        const { secretKey, ...agent } = await operator.register();
        await keyFile.writeFile(`${secretKey}\n`);
        await keyFile.close();
        if (opts.out) {
          await writeFile(opts.out, JSON.stringify(agent.credential, null, 2));
        }
        // The private key is never printed — stdout ends up in logs.
        process.stdout.write(`${JSON.stringify({ ...agent, keyFile: opts.keyOut }, null, 2)}\n`);
      } catch (error) {
        // No agent was registered for this key: leave nothing behind.
        await keyFile.close();
        await rm(opts.keyOut, { force: true });
        throw error;
      }
    });

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
    .requiredOption(
      "--credential <path>",
      "path to the agent's credential file (from `register --out`)",
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
        const credential = await loadCredentialFile(opts.credential);
        const secretKey = await loadAgentKey(opts.key);
        const delegation =
          opts.delegation === undefined ? undefined : await loadDelegationFile(opts.delegation);
        const input: unknown = JSON.parse(opts.input);
        const outcome = await custos({ vaultUrl: opts.vaultUrl })
          .connect(
            { credential, secretKey },
            tool,
            delegation === undefined ? undefined : { delegation },
          )
          .call(action, input);
        if (!outcome.ok) {
          process.stderr.write(`${describeRefusal(outcome.error)}\n`);
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
    .requiredOption("--to <did>", "the receiving agent's DID")
    .requiredOption(
      "--credential <path>",
      "path to this (delegating) agent's credential file (from `register --out`)",
    )
    .option("--key <path>", "path to this agent's private key (from `register`)", "agent.key")
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
        },
      ) => {
        const credential = await loadCredentialFile(opts.credential);
        const secretKey = await loadAgentKey(opts.key);
        const extending =
          opts.extending === undefined ? undefined : await loadDelegationFile(opts.extending);
        const delegation = custos({}).delegate(
          { did: agentDidOf(credential), credential, secretKey },
          {
            to: opts.to,
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
            throw new Error(`refusing to overwrite existing file ${opts.out}`);
          }
          throw error;
        }
        process.stdout.write(
          `${opts.to} may now ${actions.join(", ")} on ${tool} for this agent; give it ${opts.out}\n`,
        );
      },
    );

  program
    .command("grant")
    .description("Grant an agent access to one tool (build plan Phase 4: agent × tool allowlist)")
    .argument("<tool>", "tool name, e.g. stripe")
    .requiredOption(
      "--credential <path>",
      "path to the agent's credential file (from `register --out`)",
    )
    .option("--vault-url <url>", "vault service base URL", "http://localhost:4002")
    .action(async (tool: string, opts: { credential: string; vaultUrl: string }) => {
      const operator = await operatorCustos({ vaultUrl: opts.vaultUrl });
      const credential = await loadCredentialFile(opts.credential);
      const result = await operator.grant({ did: agentDidOf(credential) }, tool);
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    });

  program
    .command("audit-log")
    .description(
      "Pull and independently verify the sealed audit log (ADR 0017) for an agent (or every agent)",
    )
    .argument("[agentDid]", "did:web DID to filter to, from an agent's credential's issuer")
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
      "did:web:localhost%3A4001",
    )
    .action(async (agentDid: string | undefined, opts: AuditLogOptions) => {
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
        process.stderr.write(
          `the audit log failed independent verification: ${result.error.code}\n`,
        );
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
    .command("deprovision")
    .description("Revoke an agent's identity — cuts it off from every tool it can reach")
    .argument("<agentId>", "agent id, from `custos register`'s output")
    .option("--revocation-url <url>", "revocation service base URL", "http://localhost:4003")
    .option("--reason <text>", "why this agent is being deprovisioned")
    .action(async (agentId: string, opts: { revocationUrl: string; reason?: string }) => {
      const result = await (
        await operatorCustos({ revocationUrl: opts.revocationUrl })
      ).deprovision(
        { id: agentId },
        opts.reason === undefined ? undefined : { reason: opts.reason },
      );
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    });

  return program;
}

/**
 * Runs the CLI for real: a failed command (a denied call, an unreachable
 * service) is reported as one line on stderr with exit code 1, not an
 * unhandled rejection's stack trace.
 */
export async function runCli(argv: readonly string[]): Promise<void> {
  try {
    await createCli().parseAsync(argv);
  } catch (error: unknown) {
    process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

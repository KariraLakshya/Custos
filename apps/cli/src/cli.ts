import { open, readFile, rm, writeFile } from "node:fs/promises";
import { createCustos, type CallDenied, type Custos, type CustosConfig } from "@custos/sdk";
import { Command } from "commander";
import { pullAuditLog } from "./audit-log.js";
import { loadCredentialFile, verifyCredentialIndependently } from "./verify.js";

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

/** Reads an agent key file as `register` writes it: 64 hex characters. */
async function loadAgentKey(path: string): Promise<string> {
  const key = (await readFile(path, "utf8")).trim();
  if (!/^[0-9a-f]{64}$/i.test(key)) {
    throw new Error(`not an agent key: ${path} (expected 64 hex characters)`);
  }
  return key;
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
  if (refusal.status === 401 || refusal.status === 403) return `denied: ${refusal.code}`;
  return `failed: ${refusal.code} (HTTP ${refusal.status}) — ${JSON.stringify(refusal.detail)}`;
}

export function createCli(): Command {
  const program = new Command()
    .name("custos")
    .description("Custos — a trust layer for AI agents")
    .version("0.0.0");

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
      // Claim the key file before registering: "wx" fails if it exists, so an
      // existing agent's key is never overwritten, and 0o600 keeps it
      // owner-only (POSIX; Windows applies its own ACLs instead).
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
        const { secretKey, ...agent } = await custos({ identityUrl: opts.identityUrl }).register();
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
    .action(
      async (
        tool: string,
        action: string,
        opts: { credential: string; key: string; vaultUrl: string; input: string },
      ) => {
        const credential = await loadCredentialFile(opts.credential);
        const secretKey = await loadAgentKey(opts.key);
        const input: unknown = JSON.parse(opts.input);
        const outcome = await custos({ vaultUrl: opts.vaultUrl })
          .connect({ credential, secretKey }, tool)
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
    .command("grant")
    .description("Grant an agent access to one tool (build plan Phase 4: agent × tool allowlist)")
    .argument("<tool>", "tool name, e.g. stripe")
    .requiredOption(
      "--credential <path>",
      "path to the agent's credential file (from `register --out`)",
    )
    .option("--vault-url <url>", "vault service base URL", "http://localhost:4002")
    .action(async (tool: string, opts: { credential: string; vaultUrl: string }) => {
      const credential = await loadCredentialFile(opts.credential);
      const result = await custos({ vaultUrl: opts.vaultUrl }).grant(
        { did: agentDidOf(credential) },
        tool,
      );
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    });

  program
    .command("audit-log")
    .description("Pull and independently verify the signed audit log for an agent (or every agent)")
    .argument("[agentDid]", "did:web DID to filter to, from an agent's credential's issuer")
    .option("--audit-url <url>", "audit service base URL", "http://localhost:4004")
    .action(async (agentDid: string | undefined, opts: { auditUrl: string }) => {
      const entries = await pullAuditLog({ auditUrl: opts.auditUrl, agentDid });
      process.stdout.write(`${JSON.stringify(entries, null, 2)}\n`);
      if (entries.some((entry) => !entry.verified)) {
        process.stderr.write("one or more records failed independent verification\n");
        process.exitCode = 1;
      }
    });

  program
    .command("deprovision")
    .description("Revoke an agent's identity — cuts it off from every tool it can reach")
    .argument("<agentId>", "agent id, from `custos register`'s output")
    .option("--revocation-url <url>", "revocation service base URL", "http://localhost:4003")
    .option("--reason <text>", "why this agent is being deprovisioned")
    .action(async (agentId: string, opts: { revocationUrl: string; reason?: string }) => {
      const result = await custos({ revocationUrl: opts.revocationUrl }).deprovision(
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

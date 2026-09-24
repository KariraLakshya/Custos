import { writeFile } from "node:fs/promises";
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
    .action(async (opts: { identityUrl: string; out?: string }) => {
      const agent = await custos({ identityUrl: opts.identityUrl }).register();
      if (opts.out) {
        await writeFile(opts.out, JSON.stringify(agent.credential, null, 2));
      }
      process.stdout.write(`${JSON.stringify(agent, null, 2)}\n`);
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
    .option("--vault-url <url>", "vault service base URL", "http://localhost:4002")
    .option("--input <json>", "JSON input for the action", "{}")
    .action(
      async (
        tool: string,
        action: string,
        opts: { credential: string; vaultUrl: string; input: string },
      ) => {
        const credential = await loadCredentialFile(opts.credential);
        const input: unknown = JSON.parse(opts.input);
        const outcome = await custos({ vaultUrl: opts.vaultUrl })
          .connect({ credential }, tool)
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
        { did: credential.issuer },
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

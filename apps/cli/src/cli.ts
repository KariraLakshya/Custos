import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import { pullAuditLog } from "./audit-log.js";
import { deprovisionAgent } from "./deprovision.js";
import { grantToolAccess } from "./grant.js";
import { registerAgent } from "./register.js";
import { loadAgentCredential, useTool } from "./use.js";
import { loadCredentialFile, verifyCredentialIndependently } from "./verify.js";

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
      const result = await registerAgent(opts.identityUrl);
      if (opts.out) {
        await writeFile(opts.out, JSON.stringify(result.credential, null, 2));
      }
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
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
        const credential = await loadAgentCredential(opts.credential);
        const input: unknown = JSON.parse(opts.input);
        const outcome = await useTool({ vaultUrl: opts.vaultUrl, credential, tool, action, input });
        process.stdout.write(`${JSON.stringify(outcome, null, 2)}\n`);
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
      const credential = await loadAgentCredential(opts.credential);
      const result = await grantToolAccess({
        vaultUrl: opts.vaultUrl,
        agentDid: credential.issuer,
        tool,
      });
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
      const result = await deprovisionAgent({
        revocationUrl: opts.revocationUrl,
        agentId,
        ...(opts.reason === undefined ? {} : { reason: opts.reason }),
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    });

  return program;
}

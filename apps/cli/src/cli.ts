import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import { registerAgent } from "./register.js";
import { loadAgentCredential, useTool } from "./use.js";
import { loadCredentialFile, verifyCredentialIndependently } from "./verify.js";

// deprovision subcommand lands in Phase 3.
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

  return program;
}

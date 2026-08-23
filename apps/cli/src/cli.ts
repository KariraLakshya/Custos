import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import { registerAgent } from "./register.js";
import { loadCredentialFile, verifyCredentialIndependently } from "./verify.js";

// connect/deprovision subcommands land in Phase 2/3.
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

  return program;
}

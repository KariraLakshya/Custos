import { Command } from "commander";

// register/connect/deprovision subcommands land in Phase 5.
export function createCli(): Command {
  return new Command()
    .name("custos")
    .description("Custos — a trust layer for AI agents")
    .version("0.0.0");
}

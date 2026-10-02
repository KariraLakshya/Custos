import {
  ALL_SCOPES,
  OPERATOR_SCOPES,
  type ApiKeyStore,
  type PrincipalKind,
  type Scope,
} from "@custos/control-plane-auth";
import { Command, InvalidArgumentError } from "commander";

const DURATION = /^([1-9][0-9]{0,4})([dh])$/;

/** `90d` / `12h` → milliseconds. */
export function parseDuration(value: string): number {
  const match = DURATION.exec(value);
  if (!match) throw new InvalidArgumentError(`expected a duration like 90d or 12h, got "${value}"`);
  const hours = match[2] === "d" ? Number(match[1]) * 24 : Number(match[1]);
  return hours * 60 * 60_000;
}

function parseKind(value: string): PrincipalKind {
  if (value !== "operator" && value !== "service") {
    throw new InvalidArgumentError(`expected operator or service, got "${value}"`);
  }
  return value;
}

export interface AdminDeps {
  readonly store: ApiKeyStore;
  readonly clock: { now(): Date };
  readonly out: (line: string) => void;
}

/**
 * `custos-admin`: creates, lists and revokes control-plane API keys by
 * talking to the database directly — the same trust level as running
 * migrations. There is deliberately no HTTP route for this (ADR 0008 §6).
 */
export function createAdminCli(deps: AdminDeps): Command {
  const program = new Command()
    .name("custos-admin")
    .description("Custos administration — needs direct database access (DATABASE_URL)")
    .exitOverride();

  const key = program.command("key").description("Manage operator and service API keys");

  key
    .command("create")
    .description("Create an API key. The key is printed once and can't be retrieved again.")
    .requiredOption("--kind <kind>", "operator or service", parseKind)
    .requiredOption("--name <name>", "who or what holds the key, for the audit trail")
    .requiredOption("--scopes <scopes>", `comma-separated: ${ALL_SCOPES.join(", ")}`)
    .option(
      "--expires-in <duration>",
      "lifetime, e.g. 90d or 12h",
      parseDuration,
      parseDuration("90d"),
    )
    .action(
      async (options: { kind: PrincipalKind; name: string; scopes: string; expiresIn: number }) => {
        const now = deps.clock.now();
        const result = await deps.store.create({
          kind: options.kind,
          name: options.name,
          scopes: options.scopes
            .split(",")
            .map((scope) => scope.trim())
            .filter(Boolean),
          expiresAt: new Date(now.getTime() + options.expiresIn),
          now,
        });
        if (!result.ok) {
          const detail = "scope" in result.error ? `: ${result.error.scope}` : "";
          throw new Error(`key not created — ${result.error.code}${detail}`);
        }
        deps.out(`id:  ${result.id}`);
        deps.out(`key: ${result.token}`);
        deps.out("Store the key now: it is shown once and only its hash is kept.");
      },
    );

  key
    .command("list")
    .description("List keys (never their secrets)")
    .action(async () => {
      const now = deps.clock.now().getTime();
      for (const k of await deps.store.list()) {
        const status =
          k.revokedAt !== null ? "revoked" : k.expiresAt.getTime() <= now ? "expired" : "active";
        deps.out(
          [k.id, k.kind, status, k.name, k.scopes.join(","), k.expiresAt.toISOString()].join("\t"),
        );
      }
    });

  key
    .command("revoke")
    .description("Revoke a key by id; it stops working on its next use")
    .argument("<id>", "key id, from `key list` or `key create`")
    .action(async (id: string) => {
      if (!(await deps.store.revoke(id, deps.clock.now()))) throw new Error(`no such key: ${id}`);
      deps.out(`revoked ${id}`);
    });

  program
    .command("dev-keys")
    .description(
      "Create a local development key set: one operator key and the identity and vault service keys",
    )
    .option("--shell <shell>", "bash or powershell", parseShell, "bash")
    .option(
      "--expires-in <duration>",
      "lifetime, e.g. 90d or 12h",
      parseDuration,
      parseDuration("90d"),
    )
    .action(async (options: { shell: Shell; expiresIn: number }) => {
      const now = deps.clock.now();
      const expiresAt = new Date(now.getTime() + options.expiresIn);
      deps.out("# Custos development keys. Each is shown once; set each in the terminal named.");
      for (const key of DEV_KEYS) {
        const result = await deps.store.create({ ...key, expiresAt, now });
        if (!result.ok) throw new Error(`dev key ${key.name} not created — ${result.error.code}`);
        deps.out(`# ${key.usedBy}`);
        deps.out(assignment(options.shell, key.variable, result.token));
      }
    });

  return program;
}

type Shell = "bash" | "powershell";

function parseShell(value: string): Shell {
  if (value !== "bash" && value !== "powershell") {
    throw new InvalidArgumentError(`expected bash or powershell, got "${value}"`);
  }
  return value;
}

/** Which key each local process needs (ADR 0008 §3, §6). */
const DEV_KEYS: readonly {
  readonly variable: string;
  readonly usedBy: string;
  readonly kind: PrincipalKind;
  readonly name: string;
  readonly scopes: readonly Scope[];
}[] = [
  {
    variable: "CUSTOS_OPERATOR_KEY",
    usedBy: "the terminal you run the custos CLI, the SDK or the vault seed command in",
    kind: "operator",
    name: "dev-operator",
    scopes: OPERATOR_SCOPES,
  },
  {
    variable: "IDENTITY_SERVICE_KEY",
    usedBy: "the identity service's terminal",
    kind: "service",
    name: "dev-identity",
    scopes: ["status:allocate"],
  },
  {
    variable: "VAULT_SERVICE_KEY",
    usedBy: "the vault's terminal",
    kind: "service",
    name: "dev-vault",
    scopes: ["audit:write"],
  },
];

function assignment(shell: Shell, variable: string, value: string): string {
  // Keys are [A-Za-z0-9_-] only, so no quoting or escaping is ever needed.
  return shell === "bash" ? `export ${variable}=${value}` : `$env:${variable} = "${value}"`;
}

/** Runs the CLI; failures print one `error:` line and set exit code 1. */
export async function runAdminCli(argv: readonly string[], deps: AdminDeps): Promise<void> {
  try {
    await createAdminCli(deps).parseAsync(argv);
  } catch (error: unknown) {
    // Commander has already printed its own usage errors and help.
    const code = (error as { code?: unknown }).code;
    if (code === "commander.helpDisplayed" || code === "commander.version") return;
    if (typeof code !== "string" || !code.startsWith("commander.")) {
      process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
    }
    process.exitCode = 1;
  }
}

import type { ApiKeyStore } from "@custos/control-plane-auth";
import { DEV_KEYS } from "./admin.js";

/** A started process, as much of it as the demo needs. */
export interface DemoChild {
  onExit(callback: (code: number | null) => void): void;
  kill(): void;
}

export interface DemoDeps {
  readonly store: ApiKeyStore;
  readonly clock: { now(): Date };
  readonly out: (line: string) => void;
  /** Starts `node <script>` in `cwd` with exactly `env`. */
  readonly spawn: (
    script: string,
    options: { cwd: string; env: Record<string, string> },
  ) => DemoChild;
  readonly fetch: typeof fetch;
  readonly sleep: (ms: number) => Promise<void>;
  readonly isPortFree: (port: number) => Promise<boolean>;
  readonly randomHex: (bytes: number) => string;
  /** The environment the demo was started from. Only used for seeds to reuse. */
  readonly baseEnv: Readonly<Record<string, string | undefined>>;
  readonly databaseUrl: string;
  readonly repoRoot: string;
}

export interface DemoHandle {
  /** Resolves when the demo ends: a stop request, or a service dying. */
  readonly finished: Promise<string>;
  /** Kills the services and revokes the demo keys. */
  stop(): Promise<void>;
  /** Synchronous kill, for a process `exit` handler. */
  kill(): void;
}

/** Demo keys live this long; they are also revoked on a clean stop. */
export const DEMO_KEY_LIFETIME_MS = 12 * 60 * 60 * 1000;

const HEX_32_BYTES = /^[0-9a-f]{64}$/i;
const READY_ATTEMPTS = 150;
const READY_POLL_MS = 200;

/** Variable families a service reads. Anything of these left in the shell is dropped. */
const OWNED_PREFIXES = ["CUSTOS_", "IDENTITY_", "VAULT_", "REVOCATION_", "AUDIT_", "MTLS_"];
const OWNED_NAMES = ["PORT", "DATABASE_URL"];

export interface ServiceSpec {
  readonly name: string;
  readonly dir: string;
  readonly port: number;
  readonly readyPath: string;
}

// Start order matters: revocation and identity call audit; identity and the
// vault call revocation.
const SERVICES: readonly ServiceSpec[] = [
  { name: "audit", dir: "services/audit", port: 4004, readyPath: "/health" },
  { name: "revocation", dir: "services/revocation", port: 4003, readyPath: "/health" },
  { name: "identity", dir: "services/identity", port: 4001, readyPath: "/health" },
  { name: "vault", dir: "services/vault", port: 4002, readyPath: "/health" },
  { name: "dashboard", dir: "apps/dashboard", port: 4005, readyPath: "/" },
];

type Secrets = Readonly<Record<string, string>>;

/** Only the settings that service reads, never another service's secret. */
function ownSettings(service: string, keys: Secrets, seeds: Secrets): Record<string, string> {
  switch (service) {
    case "revocation":
      return {
        REVOCATION_SERVICE_KEY: keys["REVOCATION_SERVICE_KEY"]!,
        REVOCATION_SIGNING_SEED: seeds["REVOCATION_SIGNING_SEED"]!,
      };
    case "identity":
      return {
        IDENTITY_SERVICE_KEY: keys["IDENTITY_SERVICE_KEY"]!,
        IDENTITY_ISSUER_SEED: seeds["IDENTITY_ISSUER_SEED"]!,
      };
    case "vault":
      return {
        VAULT_SERVICE_KEY: keys["VAULT_SERVICE_KEY"]!,
        VAULT_MASTER_KEY: seeds["VAULT_MASTER_KEY"]!,
      };
    default:
      return {};
  }
}

/**
 * The environment for one service: the shell's, minus every variable a
 * Custos service reads (a leftover `VAULT_MTLS_CERT` would collide with the
 * key given here), plus exactly this service's own settings.
 */
export function buildServiceEnv(
  service: ServiceSpec,
  params: {
    readonly baseEnv: Readonly<Record<string, string | undefined>>;
    readonly databaseUrl: string;
    readonly keys: Secrets;
    readonly seeds: Secrets;
  },
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(params.baseEnv)) {
    if (value === undefined) continue;
    if (OWNED_NAMES.includes(name) || OWNED_PREFIXES.some((prefix) => name.startsWith(prefix))) {
      continue;
    }
    env[name] = value;
  }
  return {
    ...env,
    PORT: String(service.port),
    DATABASE_URL: params.databaseUrl,
    ...ownSettings(service.name, params.keys, params.seeds),
  };
}

/** A seed already in the environment is reused, so earlier credentials stay valid. */
function resolveSeeds(deps: DemoDeps): Secrets {
  const seeds: Record<string, string> = {};
  for (const name of ["IDENTITY_ISSUER_SEED", "REVOCATION_SIGNING_SEED", "VAULT_MASTER_KEY"]) {
    const existing = deps.baseEnv[name];
    seeds[name] =
      existing !== undefined && HEX_32_BYTES.test(existing) ? existing : deps.randomHex(32);
  }
  return seeds;
}

async function waitUntilReady(
  deps: DemoDeps,
  service: ServiceSpec,
  hasExited: () => boolean,
): Promise<boolean> {
  const url = `http://localhost:${service.port}${service.readyPath}`;
  for (let attempt = 0; attempt < READY_ATTEMPTS; attempt += 1) {
    if (hasExited()) return false;
    try {
      const response = await deps.fetch(url);
      // Re-check: an old process may have answered while this one died.
      if (response.ok && !hasExited()) return true;
    } catch {
      // not listening yet
    }
    await deps.sleep(READY_POLL_MS);
  }
  return false;
}

/**
 * `custos-admin demo`: starts the five local services with generated keys
 * and seeded stand-in tools, so the README walkthrough works with one
 * command. Everything generated lives in memory and in the database only:
 * seeds are never printed or written to disk, and the API keys it creates
 * are short-lived and revoked on stop.
 */
export async function startDemo(deps: DemoDeps): Promise<DemoHandle> {
  const busy: number[] = [];
  for (const service of SERVICES) {
    if (!(await deps.isPortFree(service.port))) busy.push(service.port);
  }
  if (busy.length > 0) {
    throw new Error(
      `port${busy.length > 1 ? "s" : ""} ${[...busy].sort((a, b) => a - b).join(", ")} already in use. Stop whatever is ` +
        "running there (an earlier demo or README run); on Windows, a port reserved by WinNAT " +
        "fails the same way (see docs/state.md, Gotchas).",
    );
  }

  const now = deps.clock.now();
  const expiresAt = new Date(now.getTime() + DEMO_KEY_LIFETIME_MS);
  const keys: Record<string, string> = {};
  const keyIds: string[] = [];
  for (const key of DEV_KEYS) {
    const created = await deps.store.create({
      kind: key.kind,
      name: `demo-${key.name}`,
      scopes: key.scopes,
      expiresAt,
      now,
    });
    if (!created.ok) throw new Error(`demo key ${key.name} not created: ${created.error.code}`);
    keys[key.variable] = created.token;
    keyIds.push(created.id);
  }
  const seeds = resolveSeeds(deps);

  const children: DemoChild[] = [];
  let stopped = false;
  let finish: (reason: string) => void = () => {};
  const finished = new Promise<string>((resolve) => {
    finish = resolve;
  });

  const kill = (): void => {
    for (const child of children) child.kill();
  };
  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    kill();
    const revokedAt = deps.clock.now();
    await Promise.all(keyIds.map((id) => deps.store.revoke(id, revokedAt)));
    finish("stopped");
  };

  try {
    for (const service of SERVICES) {
      let exited = false;
      const child = deps.spawn(`${deps.repoRoot}/${service.dir}/dist/index.js`, {
        cwd: `${deps.repoRoot}/${service.dir}`,
        env: buildServiceEnv(service, {
          baseEnv: deps.baseEnv,
          databaseUrl: deps.databaseUrl,
          keys,
          seeds,
        }),
      });
      children.push(child);
      child.onExit((code) => {
        exited = true;
        if (!stopped) {
          deps.out(
            `${service.name} stopped unexpectedly (exit ${code ?? "signal"}); shutting down`,
          );
          void stop();
        }
      });
      if (!(await waitUntilReady(deps, service, () => exited))) {
        throw new Error(
          `${service.name} did not start (port ${service.port}); see its output above`,
        );
      }
    }

    for (const tool of ["mock-database", "mock-slack"]) {
      const response = await deps.fetch("http://localhost:4002/credentials", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${keys["CUSTOS_OPERATOR_KEY"]}`,
        },
        body: JSON.stringify({ tool, secret: "any-placeholder-secret" }),
      });
      if (!response.ok)
        throw new Error(`seeding ${tool} failed: vault returned ${response.status}`);
    }
  } catch (error: unknown) {
    await stop();
    throw error;
  }

  printBanner(deps, keys["CUSTOS_OPERATOR_KEY"]!);
  return { finished, stop, kill };
}

function printBanner(deps: DemoDeps, operatorKey: string): void {
  const lines = [
    "",
    "Custos demo is running.",
    "",
    "  dashboard   http://localhost:4005   (keep it open: every allow and deny appears live)",
    "  identity    http://localhost:4001",
    "  vault       http://localhost:4002",
    "  revocation  http://localhost:4003",
    "  audit       http://localhost:4004",
    "",
    "Tools mock-database and mock-slack are stored. In a NEW terminal, in an EMPTY directory",
    "(register won't overwrite an agent.key from an earlier run), set your operator key:",
    "",
    `  bash / zsh   export CUSTOS_OPERATOR_KEY=${operatorKey}`,
    `  PowerShell   $env:CUSTOS_OPERATOR_KEY = "${operatorKey}"`,
    "",
    "then follow README step 4 (custos register, grant, use, deprovision), with:",
    "",
    `  bash / zsh   alias custos="node ${deps.repoRoot}/apps/cli/dist/bin.js"`,
    `  PowerShell   function custos { node "${deps.repoRoot}/apps/cli/dist/bin.js" @args }`,
    "",
    "Each demo run uses new keys, so credentials from an earlier run no longer verify,",
    "unless IDENTITY_ISSUER_SEED, REVOCATION_SIGNING_SEED and VAULT_MASTER_KEY were set first.",
    "The operator key above expires in 12 hours and is revoked when you press Ctrl-C.",
    "",
  ];
  for (const line of lines) deps.out(line);
}

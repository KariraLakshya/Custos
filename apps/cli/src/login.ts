import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** Where `custos login` keeps the operator key an SSO login issued (ADR 0010). */
export function defaultOperatorKeyFile(): string {
  return process.env.CUSTOS_OPERATOR_KEY_FILE ?? join(homedir(), ".custos", "operator.key");
}

/**
 * The operator key for operator commands: `CUSTOS_OPERATOR_KEY` (an API key,
 * for scripts) first, else the key file `custos login` wrote. `undefined`
 * when neither exists.
 */
export async function findOperatorKey(
  file = defaultOperatorKeyFile(),
): Promise<string | undefined> {
  if (process.env.CUSTOS_OPERATOR_KEY) return process.env.CUSTOS_OPERATOR_KEY;
  try {
    const key = (await readFile(file, "utf8")).trim();
    return key === "" ? undefined : key;
  } catch {
    return undefined;
  }
}

/** Best effort: open `url` in the default browser, without a shell. */
export function openInBrowser(url: string): void {
  const [command, args] =
    process.platform === "win32"
      ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
      : process.platform === "darwin"
        ? ["open", [url]]
        : ["xdg-open", [url]];
  try {
    const child = spawn(command, args, { detached: true, stdio: "ignore" });
    child.on("error", () => {});
    child.unref();
  } catch {
    // The URL is printed too, so a missing opener costs nothing.
  }
}

export interface LoginDeps {
  readonly fetchImpl?: typeof fetch;
  readonly openBrowser?: (url: string) => void;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly out: (line: string) => void;
}

/**
 * `custos login` (ADR 0010 §2): starts an SSO login on the identity
 * service, sends the person to their company sign-in page, waits for it to
 * finish, and writes the operator key it issues to `keyFile`, owner-only.
 * The key is never printed: stdout ends up in logs.
 */
export async function login(
  options: {
    readonly identityUrl: string;
    readonly keyFile: string;
    readonly browser: boolean;
    readonly timeoutMs?: number;
    readonly pollMs?: number;
  },
  deps: LoginDeps,
): Promise<{ readonly name: string; readonly expiresAt: string }> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const sleep = deps.sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms)));
  const base = options.identityUrl.replace(/\/$/, "");

  const started = await fetchImpl(`${base}/operator/login`, { method: "POST" });
  if (started.status === 404) {
    throw new Error(`the identity service at ${base} has no SSO configured`);
  }
  if (started.status !== 201) {
    throw new Error(`could not start a login: identity service returned ${started.status}`);
  }
  const { loginId, authorizationUrl } = (await started.json()) as {
    loginId: string;
    authorizationUrl: string;
  };

  deps.out("Sign in with your company account in the browser:");
  deps.out(`  ${authorizationUrl}`);
  if (options.browser) (deps.openBrowser ?? openInBrowser)(authorizationUrl);

  const deadline = Date.now() + (options.timeoutMs ?? 5 * 60_000);
  for (;;) {
    const polled = await fetchImpl(`${base}/operator/login/${loginId}`);
    if (polled.status === 200) {
      const result = (await polled.json()) as {
        operatorKey: string;
        name: string;
        expiresAt: string;
      };
      await mkdir(dirname(options.keyFile), { recursive: true, mode: 0o700 });
      await writeFile(options.keyFile, `${result.operatorKey}\n`, { mode: 0o600 });
      return { name: result.name, expiresAt: result.expiresAt };
    }
    if (polled.status === 401) {
      const body = (await polled.json()) as { error?: { code?: string } };
      const code = body.error?.code ?? "UNKNOWN";
      throw new Error(
        code === "NO_MAPPED_GROUP"
          ? "signed in, but your account isn't in a group allowed to administer Custos"
          : `sign-in refused (${code})`,
      );
    }
    if (polled.status !== 202) {
      throw new Error(`login expired or unknown (identity service returned ${polled.status})`);
    }
    if (Date.now() >= deadline) throw new Error("timed out waiting for the browser sign-in");
    await sleep(options.pollMs ?? 1_000);
  }
}

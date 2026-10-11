import { execFile } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface OwnerOnlyDeps {
  readonly platform?: NodeJS.Platform;
  readonly run?: (file: string, args: readonly string[]) => Promise<string>;
}

export async function runCommand(file: string, args: readonly string[]): Promise<string> {
  const { stdout } = await execFileAsync(file, [...args], { windowsHide: true });
  return stdout;
}

/**
 * Makes a secret file readable by its owner alone.
 *
 * POSIX does that with the `0o600` the file is opened with. Windows ignores
 * that mode: the file inherits its folder's ACL, which on a non-system drive
 * can grant `Authenticated Users` write access. There the inherited entries
 * are removed and only the current user is granted access.
 *
 * Call it before the secret is written. It throws if the ACL cannot be
 * changed, so the caller never leaves a readable key behind.
 */
export async function restrictToOwner(path: string, deps: OwnerOnlyDeps = {}): Promise<void> {
  if ((deps.platform ?? process.platform) !== "win32") return;
  const run = deps.run ?? runCommand;
  // System32 binaries by absolute path, so a lookalike earlier on PATH cannot
  // stand in (Git for Windows ships its own `whoami`, which prints no domain).
  const system32 = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
  // Granted by SID: account names icacls cannot resolve (some Azure AD names)
  // would otherwise make registering fail. CSV row: "DOMAIN\user","S-1-5-...".
  const row = await run(join(system32, "whoami.exe"), ["/user", "/fo", "csv", "/nh"]);
  const sid = /"(S-1-[0-9-]+)"/.exec(row)?.[1];
  if (sid === undefined) {
    throw new Error(`cannot restrict ${path}: unable to determine current user`);
  }
  await run(join(system32, "icacls.exe"), [path, "/inheritance:r", "/grant:r", `*${sid}:F`]);
}

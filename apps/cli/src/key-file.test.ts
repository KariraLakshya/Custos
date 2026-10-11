import { execFile } from "node:child_process";
import { mkdtemp, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { restrictToOwner } from "./key-file.js";

const execFileAsync = promisify(execFile);

describe("restrictToOwner", () => {
  it("does nothing off Windows, where the 0o600 open mode already applies", async () => {
    const calls: string[] = [];
    await restrictToOwner("agent.key", {
      platform: "linux",
      run: async (file) => {
        calls.push(file);
        return "";
      },
    });
    expect(calls).toEqual([]);
  });

  it("removes inherited entries and grants only the current user on Windows", async () => {
    const calls: Array<readonly [string, readonly string[]]> = [];
    await restrictToOwner("C:\\keys\\agent.key", {
      platform: "win32",
      run: async (file, args) => {
        calls.push([file, args]);
        return file.endsWith("whoami.exe") ? '"HOST\\alice","S-1-5-21-1-2-3-1001"\r\n' : "";
      },
    });
    expect(calls[0]?.[1]).toEqual(["/user", "/fo", "csv", "/nh"]);
    expect(calls[1]?.[0]).toMatch(/System32.icacls\.exe$/);
    expect(calls[1]?.[1]).toEqual([
      "C:\\keys\\agent.key",
      "/inheritance:r",
      "/grant:r",
      "*S-1-5-21-1-2-3-1001:F",
    ]);
  });

  it("fails rather than leave the file open when the ACL cannot be changed", async () => {
    await expect(
      restrictToOwner("agent.key", {
        platform: "win32",
        run: async (file) => {
          if (file.endsWith("icacls.exe")) throw new Error("Access is denied");
          return '"HOST\\alice","S-1-5-21-1-2-3-1001"';
        },
      }),
    ).rejects.toThrow("Access is denied");
  });

  it("fails when the current user cannot be determined", async () => {
    await expect(
      restrictToOwner("agent.key", { platform: "win32", run: async () => "  \n" }),
    ).rejects.toThrow("unable to determine current user");
  });

  // Reads the real ACL back, the way the original problem was measured.
  describe.skipIf(process.platform !== "win32")("on a real Windows file", () => {
    let dir: string;
    beforeEach(async () => {
      dir = await mkdtemp(join(tmpdir(), "custos-key-"));
    });
    afterEach(async () => {
      await rm(dir, { recursive: true, force: true });
    });

    it("leaves the current user as the only principal in the ACL", async () => {
      const file = join(dir, "agent.key");
      // Held open while restricted, as `register` does.
      const handle = await open(file, "wx", 0o600);

      const system32 = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
      const icacls = join(system32, "icacls.exe");

      // The starting point: inherited entries beyond the owner.
      const { stdout: before } = await execFileAsync(icacls, [file]);
      expect(before).toMatch(/SYSTEM|Administrators/);

      await restrictToOwner(file);
      await handle.writeFile("secret\n");
      await handle.close();

      const { stdout: me } = await execFileAsync(join(system32, "whoami.exe"));
      const { stdout: acl } = await execFileAsync(icacls, [file]);
      const entries = acl
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.includes(":(") || line.includes(":\\"))
        .map((line) => line.replace(file, "").trim());
      expect(entries).toHaveLength(1);
      expect(entries[0]?.toLowerCase().startsWith(me.trim().toLowerCase())).toBe(true);
      expect(acl).not.toMatch(/Authenticated Users|Everyone|BUILTIN\\Users|Administrators|SYSTEM/);
    });
  });
});

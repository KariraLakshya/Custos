import { access, mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { login } from "./login.js";

vi.mock("./key-file.js", () => ({
  restrictToOwner: async () => {
    throw new Error("Access is denied");
  },
}));

const OPERATOR_KEY = ["custos", "operator", "0123456789abcdef", "s".repeat(43)].join("_");

describe("custos login when the key file cannot be locked down", () => {
  it("fails and leaves no key file behind, not even the previous one emptied", async () => {
    const dir = await mkdtemp(join(tmpdir(), "custos-login-"));
    const file = join(dir, "operator.key");
    await mkdir(dir, { recursive: true });
    await writeFile(file, "previous\n");
    const fetchImpl = vi.fn(async (input: string | URL | Request) =>
      String(input).endsWith("/operator/login")
        ? new Response(
            JSON.stringify({ loginId: "a".repeat(32), authorizationUrl: "https://x.test" }),
            {
              status: 201,
            },
          )
        : new Response(JSON.stringify({ operatorKey: OPERATOR_KEY, name: "a", expiresAt: "x" }), {
            status: 200,
          }),
    );

    await expect(
      login(
        { identityUrl: "http://identity.test", keyFile: file, browser: false },
        { fetchImpl: fetchImpl as unknown as typeof fetch, sleep: async () => {}, out: () => {} },
      ),
    ).rejects.toThrow("Access is denied");

    await expect(access(file)).rejects.toThrow();
  });
});

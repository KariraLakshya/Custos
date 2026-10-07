import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { findOperatorKey, login } from "./login.js";

const OPERATOR_KEY = ["custos", "operator", "0123456789abcdef", "s".repeat(43)].join("_");
const LOGIN_ID = "a".repeat(32);

/** A scripted identity service: the login start, then each poll's answer in turn. */
function identity(polls: Array<{ status: number; body?: unknown }>, start = 201) {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url);
    if (url.endsWith("/operator/login")) {
      return new Response(
        JSON.stringify({ loginId: LOGIN_ID, authorizationUrl: "https://login.acme.test/auth?x=1" }),
        { status: start },
      );
    }
    const next = polls.shift() ?? { status: 202 };
    return new Response(next.body === undefined ? null : JSON.stringify(next.body), {
      status: next.status,
    });
  });
  return { fetchImpl: fetchImpl as unknown as typeof fetch, calls };
}

async function keyFile() {
  return join(await mkdtemp(join(tmpdir(), "custos-login-")), "nested", "operator.key");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("custos login (ADR 0010)", () => {
  it("opens the sign-in page, waits, and saves the key owner-only without printing it", async () => {
    const { fetchImpl, calls } = identity([
      { status: 202 },
      {
        status: 200,
        body: {
          operatorKey: OPERATOR_KEY,
          name: "alice@acme.test",
          expiresAt: "2026-10-08T20:00:00.000Z",
        },
      },
    ]);
    const lines: string[] = [];
    const opened: string[] = [];
    const file = await keyFile();
    const result = await login(
      { identityUrl: "http://identity.test/", keyFile: file, browser: true },
      {
        fetchImpl,
        openBrowser: (url) => opened.push(url),
        sleep: async () => {},
        out: (l) => lines.push(l),
      },
    );

    expect(result).toEqual({ name: "alice@acme.test", expiresAt: "2026-10-08T20:00:00.000Z" });
    expect(opened).toEqual(["https://login.acme.test/auth?x=1"]);
    expect(calls[0]).toBe("http://identity.test/operator/login");
    expect(calls.slice(1)).toEqual([
      `http://identity.test/operator/login/${LOGIN_ID}`,
      `http://identity.test/operator/login/${LOGIN_ID}`,
    ]);
    expect((await readFile(file, "utf8")).trim()).toBe(OPERATOR_KEY);
    if (process.platform !== "win32") expect((await stat(file)).mode & 0o777).toBe(0o600);
    expect(lines.join("\n")).not.toContain(OPERATOR_KEY);
    expect(lines.join("\n")).toContain("https://login.acme.test/auth?x=1");
  });

  it("doesn't open a browser with --no-browser", async () => {
    const { fetchImpl } = identity([
      { status: 200, body: { operatorKey: OPERATOR_KEY, name: "a", expiresAt: "x" } },
    ]);
    const opened: string[] = [];
    await login(
      { identityUrl: "http://identity.test", keyFile: await keyFile(), browser: false },
      { fetchImpl, openBrowser: (url) => opened.push(url), sleep: async () => {}, out: () => {} },
    );
    expect(opened).toEqual([]);
  });

  it.each([
    [{ error: { code: "NO_MAPPED_GROUP" } }, /isn't in a group allowed to administer Custos/],
    [{ error: { code: "TOKEN_REJECTED" } }, /sign-in refused \(TOKEN_REJECTED\)/],
    [{}, /sign-in refused \(UNKNOWN\)/],
  ])("reports a refused sign-in (%j) and writes no key", async (body, message) => {
    const { fetchImpl } = identity([{ status: 401, body }]);
    const file = await keyFile();
    await expect(
      login(
        { identityUrl: "http://identity.test", keyFile: file, browser: false },
        { fetchImpl, sleep: async () => {}, out: () => {} },
      ),
    ).rejects.toThrow(message);
    await expect(readFile(file, "utf8")).rejects.toThrow(/ENOENT/);
  });

  it("explains an identity service with no SSO", async () => {
    const { fetchImpl } = identity([], 404);
    await expect(
      login(
        { identityUrl: "http://identity.test", keyFile: await keyFile(), browser: false },
        { fetchImpl, out: () => {} },
      ),
    ).rejects.toThrow(/has no SSO configured/);
  });

  it("reports any other failure to start", async () => {
    const { fetchImpl } = identity([], 503);
    await expect(
      login(
        { identityUrl: "http://identity.test", keyFile: await keyFile(), browser: false },
        { fetchImpl, out: () => {} },
      ),
    ).rejects.toThrow(/could not start a login: identity service returned 503/);
  });

  it("reports an expired login", async () => {
    const { fetchImpl } = identity([{ status: 404 }]);
    await expect(
      login(
        { identityUrl: "http://identity.test", keyFile: await keyFile(), browser: false },
        { fetchImpl, sleep: async () => {}, out: () => {} },
      ),
    ).rejects.toThrow(/login expired or unknown/);
  });

  it("gives up after its timeout", async () => {
    const { fetchImpl } = identity([]);
    await expect(
      login(
        {
          identityUrl: "http://identity.test",
          keyFile: await keyFile(),
          browser: false,
          timeoutMs: 0,
        },
        { fetchImpl, sleep: async () => {}, out: () => {} },
      ),
    ).rejects.toThrow(/timed out/);
  });
});

describe("findOperatorKey", () => {
  it("prefers CUSTOS_OPERATOR_KEY", async () => {
    vi.stubEnv("CUSTOS_OPERATOR_KEY", "from-env");
    const file = await keyFile();
    expect(await findOperatorKey(file)).toBe("from-env");
  });

  it("falls back to the file custos login wrote", async () => {
    vi.stubEnv("CUSTOS_OPERATOR_KEY", "");
    const file = join(await mkdtemp(join(tmpdir(), "custos-login-")), "operator.key");
    await writeFile(file, `${OPERATOR_KEY}\n`);
    expect(await findOperatorKey(file)).toBe(OPERATOR_KEY);
  });

  it("is undefined when there is neither, or the file is empty", async () => {
    vi.stubEnv("CUSTOS_OPERATOR_KEY", "");
    expect(await findOperatorKey(await keyFile())).toBeUndefined();
    const empty = join(await mkdtemp(join(tmpdir(), "custos-login-")), "operator.key");
    await writeFile(empty, "\n");
    expect(await findOperatorKey(empty)).toBeUndefined();
  });
});

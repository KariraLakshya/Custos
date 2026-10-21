import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ApiKeyStore } from "@custos/control-plane-auth";
import { generateKeyPair, publicKeyToMultibase } from "@custos/core";
import { afterEach, describe, expect, it } from "vitest";
import { createAdminCli } from "../admin.js";
import type { PublisherRuntime } from "./cli.js";
import { SEED, issueAgentCredential, makeKit, mutableClock, type Kit } from "./testkit.js";

const kits: Kit[] = [];
afterEach(async () => {
  await Promise.all(kits.splice(0).map((k) => k.cleanup()));
});

async function setup(
  env: Record<string, string | undefined> = { CUSTOS_PUBLISHER_SIGNING_SEED: SEED },
) {
  const k = await makeKit();
  kits.push(k);
  const lines: string[] = [];
  const clock = mutableClock();
  const runtime: PublisherRuntime = { env, clock, out: (line) => void lines.push(line) };
  const run = (...args: string[]) =>
    createAdminCli({
      store: {} as ApiKeyStore,
      clock,
      out: (line) => void lines.push(line),
      publisher: runtime,
    }).parseAsync(["node", "custos-admin", "publish-status", ...args]);
  const common = [
    "--domain",
    "a.example",
    "--dir",
    join(k.dir, "publisher"),
    "--out",
    join(k.dir, "site", "status.json"),
    "--validity-seconds",
    "3600",
  ];
  return { k, lines, run, common, clock, runtime };
}

describe("publish-status", () => {
  it("init, revoke by number typed twice, stamp, and show", async () => {
    const { k, lines, run, common } = await setup();

    await run("init", ...common, "--confirm-nothing-is-published");
    expect(lines.at(-1)).toMatch(
      /^published: 0 revoked, valid 2026-10-21T10:00:00.000Z to 2026-10-21T11:00:00.000Z$/,
    );

    await run(
      "revoke",
      ...common,
      "--index",
      "77",
      "--confirm-index",
      "77",
      "--operator",
      "lakshya",
      "--reason",
      "leak",
    );
    expect(lines).toContain("revoked index 77");
    expect(lines.at(-1)).toContain("published: 1 revoked");

    await run("once", ...common);
    expect(lines.at(-1)).toContain("published: 1 revoked");

    await run("show", "--domain", "a.example", "--dir", join(k.dir, "publisher"));
    expect(lines.some((l) => l === "did:        did:web:a.example")).toBe(true);
    expect(lines.some((l) => l.startsWith("public key: z"))).toBe(true);
    expect(lines.at(-1)).toBe("journal:    1 revocation(s)");
  });

  it("revokes by credential file, naming the agent", async () => {
    const { k, lines, run, common } = await setup();
    await run("init", ...common, "--confirm-nothing-is-published");
    const identityKeys = generateKeyPair();
    const credential = await issueAgentCredential({
      identityDid: "did:web:identity.a.example",
      identityKeys,
      index: 12,
    });
    const path = join(k.dir, "agent.json");
    await writeFile(path, JSON.stringify(credential));
    await run(
      "revoke",
      ...common,
      "--credential",
      path,
      "--identity-did",
      "did:web:identity.a.example",
      "--identity-public-key",
      publicKeyToMultibase(identityKeys.publicKey),
      "--operator",
      "lakshya",
      "--reason",
      "leak",
    );
    expect(
      lines.some((l) => l.startsWith("revoked index 12 (did:web:identity.a.example:agents:")),
    ).toBe(true);
  });

  it("refuses to revoke with neither or both ways of naming the agent", async () => {
    const { lines, run, common } = await setup();
    await run("init", ...common, "--confirm-nothing-is-published");
    const before = lines.length;
    await expect(run("revoke", ...common, "--operator", "x", "--reason", "y")).rejects.toThrow(
      "either --credential",
    );
    await expect(
      run(
        "revoke",
        ...common,
        "--credential",
        "a.json",
        "--index",
        "1",
        "--confirm-index",
        "1",
        "--operator",
        "x",
        "--reason",
        "y",
      ),
    ).rejects.toThrow("either --credential");
    expect(lines.length).toBe(before);
  });

  it("explains why a mistyped confirmation changed nothing", async () => {
    const { lines, run, common } = await setup();
    await run("init", ...common, "--confirm-nothing-is-published");
    await expect(
      run(
        "revoke",
        ...common,
        "--index",
        "77",
        "--confirm-index",
        "78",
        "--operator",
        "x",
        "--reason",
        "y",
      ),
    ).rejects.toThrow("cannot be undone");
    expect(lines.join("\n")).not.toContain("revoked index");
  });

  it("requires an operator and a reason", async () => {
    const { run, common } = await setup();
    await expect(run("revoke", ...common, "--index", "1", "--confirm-index", "1")).rejects.toThrow(
      /operator/,
    );
  });

  it("refuses to start with a bad configuration, before touching any file", async () => {
    const { k, run, common } = await setup();
    const without = (flag: string) => {
      const i = common.indexOf(flag);
      return common.filter((_, j) => j !== i && j !== i + 1);
    };
    await expect(run("init", ...without("--validity-seconds"))).rejects.toThrow(
      "--validity-seconds",
    );
    await expect(run("init", ...without("--domain"))).rejects.toThrow("--domain");
    await expect(run("run", ...common)).rejects.toThrow("--stamp-seconds");
    await expect(run("run", ...common, "--stamp-seconds", "3600")).rejects.toThrow("shorter");
    await expect(readFile(join(k.dir, "publisher", "journal.jsonl"))).rejects.toThrow();
  });

  it("refuses to start without the signing seed in the environment, and never echoes it", async () => {
    const bad = "not-a-seed-but-secret-looking";
    const { lines, run, common } = await setup({ CUSTOS_PUBLISHER_SIGNING_SEED: bad });
    await expect(run("init", ...common)).rejects.toThrow("CUSTOS_PUBLISHER_SIGNING_SEED");
    expect(lines.join("\n")).not.toContain(bad);
    const none = await setup({});
    await expect(none.run("init", ...none.common)).rejects.toThrow("CUSTOS_PUBLISHER_SIGNING_SEED");
    await expect(none.run("show", "--domain", "a.example")).rejects.toThrow(
      "CUSTOS_PUBLISHER_SIGNING_SEED",
    );
  });

  it("says plainly that nothing was published when there is nothing to build on", async () => {
    const { lines, run, common } = await setup();
    await expect(run("once", ...common)).rejects.toThrow("not published");
    expect(lines.at(-1)).toContain("error: nothing to build on");
    expect(lines.at(-1)).toContain("init");
  });

  it("says plainly that initialising again was refused", async () => {
    const { lines, run, common } = await setup();
    await run("init", ...common, "--confirm-nothing-is-published");
    await expect(run("init", ...common)).rejects.toThrow("not initialised");
    expect(lines.at(-1)).toContain("refusing to initialise");
  });

  it("never prints the seed", async () => {
    const { lines, run, common } = await setup();
    await run("init", ...common, "--confirm-nothing-is-published");
    await run(
      "revoke",
      ...common,
      "--index",
      "3",
      "--confirm-index",
      "3",
      "--operator",
      "o",
      "--reason",
      "r",
    );
    await run("show", "--domain", "a.example");
    expect(lines.join("\n")).not.toContain(SEED);
  });

  it("only offers --use-database when the entry point can provide it", async () => {
    const { run, common } = await setup();
    await expect(run("init", ...common, "--use-database")).rejects.toThrow("not available");
  });

  it("reads A's database when asked, and recovers from a host copy when given its address", async () => {
    const k = await makeKit();
    kits.push(k);
    const lines: string[] = [];
    const clock = mutableClock();
    const requested: string[] = [];
    const runtime: PublisherRuntime = {
      env: { CUSTOS_PUBLISHER_SIGNING_SEED: SEED },
      clock,
      out: (line) => void lines.push(line),
      readDatabaseIndexes: async () => [4, 9],
      fetchImpl: (async (url: string) => {
        requested.push(String(url));
        return new Response(null, { status: 404 });
      }) as typeof fetch,
    };
    const common = [
      "--domain",
      "a.example",
      "--dir",
      join(k.dir, "publisher"),
      "--out",
      join(k.dir, "status.json"),
      "--validity-seconds",
      "3600",
    ];
    await createAdminCli({
      store: {} as ApiKeyStore,
      clock,
      out: () => undefined,
      publisher: runtime,
    }).parseAsync([
      "node",
      "custos-admin",
      "publish-status",
      "init",
      ...common,
      "--use-database",
      "--host-url",
      "https://lists.example/a.json",
    ]);
    expect(lines.at(-1)).toContain("published: 2 revoked");
    expect(requested).toEqual(["https://lists.example/a.json"]);
  });

  it("the host fetcher refuses an error status, an oversized body and invalid JSON", async () => {
    const k = await makeKit();
    kits.push(k);
    const clock = mutableClock();
    const responses = [
      () => new Response("x", { status: 500 }),
      () => new Response("x".repeat(2_200_000), { status: 200 }),
      () => new Response("<html>", { status: 200 }),
    ];
    for (const respond of responses) {
      const lines: string[] = [];
      const runtime: PublisherRuntime = {
        env: { CUSTOS_PUBLISHER_SIGNING_SEED: SEED },
        clock,
        out: (line) => void lines.push(line),
        fetchImpl: (async () => respond()) as typeof fetch,
      };
      const dir = join(k.dir, `p-${responses.indexOf(respond)}`);
      await expect(
        createAdminCli({
          store: {} as ApiKeyStore,
          clock,
          out: () => undefined,
          publisher: runtime,
        }).parseAsync([
          "node",
          "custos-admin",
          "publish-status",
          "init",
          "--domain",
          "a.example",
          "--dir",
          dir,
          "--out",
          join(dir, "s.json"),
          "--validity-seconds",
          "3600",
          "--host-url",
          "https://lists.example/a.json",
        ]),
      ).rejects.toThrow("not initialised");
      expect(lines.join("\n")).toContain("refusing to initialise while the host cannot be read");
    }
  });

  it("run re-signs until stopped, then returns", async () => {
    const { k, lines, run, common, runtime, clock } = await setup();
    await run("init", ...common, "--confirm-nothing-is-published");
    const controller = new AbortController();
    let sleeps = 0;
    const stopping: PublisherRuntime = {
      ...runtime,
      signal: controller.signal,
      sleep: async (ms) => {
        clock.advance(ms);
        sleeps += 1;
        if (sleeps === 2) controller.abort();
      },
    };
    await createAdminCli({
      store: {} as ApiKeyStore,
      clock,
      out: () => undefined,
      publisher: stopping,
    }).parseAsync([
      "node",
      "custos-admin",
      "publish-status",
      "run",
      ...common,
      "--stamp-seconds",
      "1200",
    ]);
    expect(lines.filter((l) => l.startsWith("published:"))).toHaveLength(3); // init plus two stamps
    expect(k.dir).toBeTruthy();
  });

  it("run stops with an error when it needs a person", async () => {
    const { lines, run, common } = await setup();
    await expect(run("run", ...common, "--stamp-seconds", "1200")).rejects.toThrow(
      "needs a person",
    );
    expect(lines.at(-1)).toContain("nothing to build on");
  });

  it("is not offered when the entry point gives no publisher runtime", async () => {
    const cli = createAdminCli({
      store: {} as ApiKeyStore,
      clock: mutableClock(),
      out: () => undefined,
    });
    expect(cli.commands.map((c) => c.name())).not.toContain("publish-status");
  });
});

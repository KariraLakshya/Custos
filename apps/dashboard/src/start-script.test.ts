import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("dashboard start script", () => {
  // Regression: `start` once ran dist/server.js, which only defines the
  // server — the process exited immediately and nothing listened on 4005.
  it("runs the entrypoint that actually starts listening", async () => {
    const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as {
      scripts: { start: string };
    };
    const target = /^node dist\/(\w+)\.js$/.exec(pkg.scripts.start)?.[1];
    expect(target).toBeDefined();

    const source = await readFile(new URL(`./${target}.ts`, import.meta.url), "utf8");
    expect(source).toMatch(/\.listen\(/);
  });
});

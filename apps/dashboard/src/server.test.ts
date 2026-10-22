import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, afterEach } from "vitest";
import { buildServer } from "./server.js";

describe("dashboard server", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server?.close(resolve));
    server = undefined;
  });

  it("serves the dashboard page on GET /", async () => {
    server = buildServer();
    await new Promise<void>((resolve) => server?.listen(4930, "127.0.0.1", resolve));

    const response = await fetch("http://127.0.0.1:4930/");

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    const body = await response.text();
    expect(body).toContain("Custos");
    expect(body).toContain("Live action feed");
  });

  it("serves the same page regardless of path", async () => {
    server = buildServer();
    await new Promise<void>((resolve) => server?.listen(4931, "127.0.0.1", resolve));

    const response = await fetch("http://127.0.0.1:4931/anything");

    expect(response.status).toBe(200);
  });

  it("serves the compiled foreign.js as a JavaScript module the browser will accept", async () => {
    const dir = await mkdtemp(join(tmpdir(), "custos-dashboard-"));
    try {
      await writeFile(join(dir, "foreign.js"), "export const marker = 1;");
      server = buildServer({ assetDir: dir });
      await new Promise<void>((resolve) => server?.listen(4932, "127.0.0.1", resolve));

      const response = await fetch("http://127.0.0.1:4932/foreign.js?v=1");

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("text/javascript; charset=utf-8");
      expect(await response.text()).toBe("export const marker = 1;");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("answers 404, not the page, when foreign.js has not been built", async () => {
    const dir = await mkdtemp(join(tmpdir(), "custos-dashboard-"));
    try {
      server = buildServer({ assetDir: dir });
      await new Promise<void>((resolve) => server?.listen(4933, "127.0.0.1", resolve));

      const response = await fetch("http://127.0.0.1:4933/foreign.js");

      expect(response.status).toBe(404);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("loads the cross-organisation panel's module separately from the rest of the page", async () => {
    server = buildServer();
    await new Promise<void>((resolve) => server?.listen(4934, "127.0.0.1", resolve));

    const body = await (await fetch("http://127.0.0.1:4934/")).text();

    // A classic script that loads the panel's module on its own, so a failed
    // import cannot take the rest of the page down with it.
    expect(body).not.toContain('<script type="module">');
    expect(body).toContain('import("/foreign.js")');
    expect(body).toContain('id="foreign-panel"');
  });
});

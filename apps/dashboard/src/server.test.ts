import { describe, expect, it, afterEach } from "vitest";
import type { Server } from "node:http";
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
});

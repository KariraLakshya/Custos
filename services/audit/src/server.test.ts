import { describe, expect, it } from "vitest";
import { buildServer } from "./server.js";

describe("audit service", () => {
  it("responds to /health", async () => {
    const app = buildServer();
    const response = await app.inject({ method: "GET", url: "/health" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", service: "audit" });
  });
});

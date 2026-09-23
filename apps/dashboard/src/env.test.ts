import { describe, expect, it } from "vitest";
import { loadDashboardEnv } from "./env.js";

describe("dashboard env", () => {
  it("defaults PORT to 4005", () => {
    expect(loadDashboardEnv({}).PORT).toBe(4005);
  });

  it("coerces PORT from a string", () => {
    expect(loadDashboardEnv({ PORT: "5000" }).PORT).toBe(5000);
  });
});

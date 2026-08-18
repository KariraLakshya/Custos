import { describe, expect, it } from "vitest";
import { baseEnvSchema, loadEnv } from "./base-env.js";

describe("loadEnv", () => {
  it("parses a valid environment", () => {
    const env = loadEnv(baseEnvSchema, { NODE_ENV: "production", LOG_LEVEL: "warn" });
    expect(env).toEqual({ NODE_ENV: "production", LOG_LEVEL: "warn" });
  });

  it("applies defaults when values are absent", () => {
    const env = loadEnv(baseEnvSchema, {});
    expect(env).toEqual({ NODE_ENV: "development", LOG_LEVEL: "info" });
  });

  it("throws on an invalid environment instead of booting", () => {
    expect(() => loadEnv(baseEnvSchema, { NODE_ENV: "staging" })).toThrow(
      /Invalid environment configuration/,
    );
  });

  it("labels a root-level issue as (root) rather than an empty path", () => {
    expect(() => loadEnv(baseEnvSchema, null as unknown as Record<string, string>)).toThrow(
      /\(root\)/,
    );
  });

  it("reads from process.env when no source is given", () => {
    const original = process.env.NODE_ENV;
    process.env.NODE_ENV = "test";
    try {
      expect(loadEnv(baseEnvSchema).NODE_ENV).toBe("test");
    } finally {
      process.env.NODE_ENV = original;
    }
  });
});

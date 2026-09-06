import { coverageConfigDefaults, defineConfig, mergeConfig, type UserConfig } from "vitest/config";

export const defaultCoverageThresholds = {
  statements: 80,
  branches: 80,
  functions: 80,
  lines: 80,
} as const;

export const coreCoverageThresholds = {
  statements: 95,
  branches: 95,
  functions: 95,
  lines: 95,
} as const;

export const baseVitestConfig = defineConfig({
  test: {
    environment: "node",
    // Vitest's 5s default is tuned for unit tests. The integration and e2e
    // suites talk to real Postgres, bind real ports, and run JSON-LD
    // canonicalization, and CI runners are markedly slower than a dev
    // machine — a marginal timeout there is a flaky build, not a real defect.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: "v8",
      enabled: true,
      reporter: ["text", "lcov"],
      thresholds: defaultCoverageThresholds,
      // Barrel re-exports and process entrypoints (I/O, no branching logic) carry no
      // testable logic of their own — excluded so they don't dilute real coverage.
      exclude: [...coverageConfigDefaults.exclude, "**/src/index.ts", "**/src/bin.ts"],
    },
  },
});

export function createVitestConfig(overrides: UserConfig = {}): UserConfig {
  return mergeConfig(baseVitestConfig, overrides);
}

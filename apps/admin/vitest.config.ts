import { configDefaults, coverageConfigDefaults } from "vitest/config";
import { createVitestConfig } from "@custos/vitest-config";
import { hermeticDatabaseSetup } from "@custos/vitest-config/hermetic-db";

export default createVitestConfig({
  test: {
    globalSetup: [hermeticDatabaseSetup],
    // The two-stack federation run is the slowest layer: `pnpm test:e2e` only.
    exclude: [...configDefaults.exclude, "**/dist/**", "**/*.e2e.test.ts"],
    coverage: {
      exclude: [...coverageConfigDefaults.exclude, "**/src/bin.ts"],
    },
  },
});

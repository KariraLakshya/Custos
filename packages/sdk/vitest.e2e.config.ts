import { defineConfig, mergeConfig } from "vitest/config";
import { createVitestConfig } from "@custos/vitest-config";
import { hermeticDatabaseSetup } from "@custos/vitest-config/hermetic-db";

export default mergeConfig(
  createVitestConfig({ test: { globalSetup: [hermeticDatabaseSetup] } }),
  defineConfig({
    test: {
      include: ["src/**/*.e2e.test.ts"],
      coverage: { enabled: false },
    },
  }),
);

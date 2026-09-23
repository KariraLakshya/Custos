import { defineConfig, mergeConfig } from "vitest/config";
import { createVitestConfig } from "@custos/vitest-config";

export default mergeConfig(
  createVitestConfig(),
  defineConfig({
    test: {
      include: ["src/**/*.e2e.test.ts"],
      coverage: { enabled: false },
    },
  }),
);

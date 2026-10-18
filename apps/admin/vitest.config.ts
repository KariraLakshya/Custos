import { coverageConfigDefaults } from "vitest/config";
import { createVitestConfig } from "@custos/vitest-config";
import { hermeticDatabaseSetup } from "@custos/vitest-config/hermetic-db";

export default createVitestConfig({
  test: {
    globalSetup: [hermeticDatabaseSetup],
    coverage: {
      exclude: [...coverageConfigDefaults.exclude, "**/src/bin.ts"],
    },
  },
});

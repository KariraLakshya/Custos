import { coverageConfigDefaults, configDefaults } from "vitest/config";
import { createVitestConfig } from "@custos/vitest-config";

export default createVitestConfig({
  test: {
    exclude: [...configDefaults.exclude, "**/*.e2e.test.ts"],
    coverage: {
      exclude: [
        ...coverageConfigDefaults.exclude,
        "**/src/index.ts",
        "**/src/bin.ts",
        "vitest.e2e.config.ts",
      ],
    },
  },
});

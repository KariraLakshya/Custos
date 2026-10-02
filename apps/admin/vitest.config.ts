import { coverageConfigDefaults } from "vitest/config";
import { createVitestConfig } from "@custos/vitest-config";

export default createVitestConfig({
  test: {
    coverage: {
      exclude: [...coverageConfigDefaults.exclude, "**/src/bin.ts"],
    },
  },
});

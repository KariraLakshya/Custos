import { coreCoverageThresholds, createVitestConfig } from "@custos/vitest-config";

export default createVitestConfig({
  test: { coverage: { thresholds: coreCoverageThresholds } },
});

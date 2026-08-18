import { describe, expect, it } from "vitest";
import { coreCoverageThresholds, createVitestConfig, defaultCoverageThresholds } from "./index.js";

// Coverage config is a discriminated union keyed on `provider`; only the
// v8/istanbul variants carry `thresholds`, so tests narrow through this helper.
function thresholdsOf(config: ReturnType<typeof createVitestConfig>) {
  const coverage = config.test?.coverage as { thresholds?: unknown } | undefined;
  return coverage?.thresholds;
}

describe("createVitestConfig", () => {
  it("applies default coverage thresholds", () => {
    const config = createVitestConfig();
    expect(thresholdsOf(config)).toEqual(defaultCoverageThresholds);
  });

  it("allows overriding thresholds for packages/core", () => {
    const config = createVitestConfig({
      test: { coverage: { thresholds: coreCoverageThresholds } },
    });
    expect(thresholdsOf(config)).toEqual(coreCoverageThresholds);
  });
});

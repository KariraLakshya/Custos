import { createVitestConfig } from "@custos/vitest-config";

export default createVitestConfig({
  test: {
    // Only the build-time page generator has logic to test; the site is content.
    include: ["lib/**/*.test.ts"],
    coverage: { include: ["lib/**/*.ts"] },
  },
});

import { createVitestConfig } from "@custos/vitest-config";

export default createVitestConfig({
  // A one-off operational script, not application logic — same rationale as
  // the shared config's index.ts/bin.ts exclusion.
  test: { coverage: { exclude: ["scripts/**"] } },
});

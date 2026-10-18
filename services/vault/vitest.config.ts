import { createVitestConfig } from "@custos/vitest-config";
import { hermeticDatabaseSetup } from "@custos/vitest-config/hermetic-db";

export default createVitestConfig({
  // A one-off operational script, not application logic — same rationale as
  // the shared config's index.ts/bin.ts exclusion.
  test: { globalSetup: [hermeticDatabaseSetup], coverage: { exclude: ["scripts/**"] } },
});

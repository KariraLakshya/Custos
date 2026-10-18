import { createVitestConfig } from "@custos/vitest-config";
import { hermeticDatabaseSetup } from "@custos/vitest-config/hermetic-db";

export default createVitestConfig({ test: { globalSetup: [hermeticDatabaseSetup] } });

import { baseConfig } from "@custos/eslint-config";

export default [
  ...baseConfig,
  {
    ignores: ["**/dist/**", "**/coverage/**", "**/.turbo/**", "**/node_modules/**"],
  },
];

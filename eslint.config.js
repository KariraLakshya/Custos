import { baseConfig } from "@custos/eslint-config";

export default [
  ...baseConfig,
  {
    ignores: ["**/dist/**", "**/coverage/**", "**/.turbo/**", "**/node_modules/**"],
  },
  {
    // Plain Node scripts (e.g. services/vault/scripts/*.mjs) run outside the
    // TypeScript project, so eslint:recommended's `no-undef` doesn't know
    // about Node's globals the way it's suppressed for .ts files.
    files: ["**/*.mjs"],
    languageOptions: {
      globals: { process: "readonly", console: "readonly", fetch: "readonly", URL: "readonly" },
    },
  },
];

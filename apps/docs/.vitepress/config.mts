import { defineConfig } from "vitepress";
import { expandRefusals } from "../lib/refusals.js";

// A static site (ADR 0023). Search is VitePress's built-in local index, built
// into the site and searched in the browser: no third-party search service.
// VitePress has no telemetry.
export default defineConfig({
  title: "Custos",
  description:
    "Custos: a trust layer for AI agents. Identity, scoped access, revocation and audit.",
  lang: "en-GB",
  srcDir: "src",
  outDir: "dist",
  cleanUrls: true,
  lastUpdated: false,
  // A broken internal link fails the build. Links to the local stack
  // (http://localhost:4005 and so on) are meant for the reader's machine.
  ignoreDeadLinks: "localhostLinks",
  markdown: {
    // The refusal-codes page is generated from @custos/contracts at build time.
    // Done in the Markdown pipeline, so the dev server, the build and the
    // search index all see the same generated text.
    config(md) {
      md.core.ruler.before("normalize", "custos-refusals", (state) => {
        state.src = expandRefusals(state.src);
      });
    },
  },
  themeConfig: {
    nav: [
      { text: "Get started", link: "/get-started/installation" },
      { text: "Optional setups", link: "/how-to/operator-sso" },
      { text: "Reference", link: "/reference/cli" },
    ],
    sidebar: [
      {
        text: "Start here",
        items: [
          { text: "Introduction", link: "/introduction" },
          { text: "Glossary", link: "/glossary" },
        ],
      },
      {
        text: "Get started",
        items: [
          { text: "Install and run", link: "/get-started/installation" },
          { text: "Your first agent (CLI)", link: "/get-started/first-agent" },
          { text: "SDK quickstart", link: "/get-started/sdk-quickstart" },
        ],
      },
      {
        text: "Optional setups",
        items: [
          { text: "Run with mTLS", link: "/how-to/mtls" },
          { text: "Operator sign-in (SSO)", link: "/how-to/operator-sso" },
          { text: "Trust another organisation", link: "/how-to/federation" },
          { text: "Keep keys in AWS KMS", link: "/how-to/kms-keys" },
          { text: "Run from container images", link: "/how-to/container-images" },
        ],
      },
      {
        text: "Help",
        items: [{ text: "Troubleshooting", link: "/how-to/troubleshooting" }],
      },
      {
        text: "Reference",
        items: [
          { text: "custos CLI", link: "/reference/cli" },
          { text: "custos-admin CLI", link: "/reference/admin-cli" },
          { text: "SDK", link: "/reference/sdk" },
          {
            text: "HTTP API",
            items: [
              { text: "Overview", link: "/reference/http/" },
              { text: "Identity", link: "/reference/http/identity" },
              { text: "Vault", link: "/reference/http/vault" },
              { text: "Revocation", link: "/reference/http/revocation" },
              { text: "Audit", link: "/reference/http/audit" },
            ],
          },
          { text: "Configuration", link: "/reference/configuration" },
          { text: "Refusal codes", link: "/reference/refusals" },
        ],
      },
    ],
    search: { provider: "local" },
    outline: { level: [2, 3] },
    footer: {
      message: "Apache-2.0. A development build: not yet hardened for production.",
    },
  },
});

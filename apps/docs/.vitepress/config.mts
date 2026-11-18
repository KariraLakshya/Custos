import { defineConfig } from "vitepress";
import { expandRefusals } from "../lib/refusals.js";

// A static site (ADR 0023). Search is VitePress's built-in local index, built
// into the site and searched in the browser: no third-party search service.
// VitePress has no telemetry.
export default defineConfig({
  title: "Custos",
  description: "Custos: a trust layer for AI agents. Identity, scoped access, revocation and audit.",
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
      { text: "Concepts", link: "/concepts/architecture" },
      { text: "How-to", link: "/how-to/troubleshooting" },
      { text: "Reference", link: "/reference/cli" },
      { text: "Security", link: "/security/" },
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
        text: "Concepts",
        items: [
          { text: "Architecture: hot path and cold path", link: "/concepts/architecture" },
          { text: "Agent identity", link: "/concepts/agent-identity" },
          { text: "Proof of possession", link: "/concepts/proof-of-possession" },
          { text: "Scoped tokens", link: "/concepts/scoped-tokens" },
          { text: "The vault", link: "/concepts/vault" },
          { text: "Policy and grants", link: "/concepts/policy-and-grants" },
          { text: "Revocation", link: "/concepts/revocation" },
          { text: "The audit ledger", link: "/concepts/audit-ledger" },
          { text: "Delegation", link: "/concepts/delegation" },
          { text: "Federation", link: "/concepts/federation" },
          { text: "Control-plane authentication", link: "/concepts/control-plane-auth" },
        ],
      },
      {
        text: "How-to guides",
        items: [
          { text: "Run with mTLS", link: "/how-to/mtls" },
          { text: "Operator sign-in (SSO)", link: "/how-to/operator-sso" },
          { text: "Trust another organisation", link: "/how-to/federation" },
          { text: "Keep keys in AWS KMS", link: "/how-to/kms-keys" },
          { text: "Run from container images", link: "/how-to/container-images" },
          { text: "Troubleshooting", link: "/how-to/troubleshooting" },
        ],
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
      {
        text: "Security",
        items: [
          { text: "Threat model summary", link: "/security/" },
          { text: "Not yet production-hardened", link: "/security/limits" },
          { text: "Reporting a vulnerability", link: "/security/disclosure" },
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

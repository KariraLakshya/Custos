import { describe, expect, it } from "vitest";
import { KNOWN_CONTEXT_URLS, staticDocumentLoader } from "./document-loader.js";

describe("staticDocumentLoader", () => {
  it("resolves every bundled context URL", async () => {
    expect(KNOWN_CONTEXT_URLS.length).toBeGreaterThan(0);
    for (const url of KNOWN_CONTEXT_URLS) {
      const result = await staticDocumentLoader(url);
      expect(result.documentUrl).toBe(url);
      expect(result.contextUrl).toBeNull();
      expect(result.document).toBeTruthy();
    }
  });

  it("includes the VC Data Model 2.0 and Ed25519Signature2020 contexts", () => {
    expect(KNOWN_CONTEXT_URLS).toContain("https://www.w3.org/ns/credentials/v2");
    expect(KNOWN_CONTEXT_URLS).toContain("https://w3id.org/security/suites/ed25519-2020/v1");
  });

  it("never performs network I/O: any unknown URL is refused, not fetched", async () => {
    await expect(staticDocumentLoader("https://example.com/not-bundled")).rejects.toThrow(
      /refusing to load unknown/i,
    );
  });
});

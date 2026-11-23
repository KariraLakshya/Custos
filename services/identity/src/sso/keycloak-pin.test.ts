import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * One Keycloak pin (CLAUDE.md §4, dependencies are attack surface): every
 * Keycloak image in the compose file, the development one and the image
 * stack's (ADR 0022), is the digest-pinned image in infra/sso/images.json,
 * which sso-keycloak.test.ts runs. A Dependabot bump of one line alone fails here.
 */
const repoRoot = resolve(__dirname, "../../../..");

describe("the Keycloak image pin", () => {
  it("is the same digest everywhere compose runs Keycloak", () => {
    const { keycloak } = JSON.parse(
      readFileSync(join(repoRoot, "infra/sso/images.json"), "utf8"),
    ) as { keycloak: string };
    expect(keycloak).toMatch(/@sha256:[0-9a-f]{64}$/);
    const compose = readFileSync(join(repoRoot, "infra/docker/docker-compose.yml"), "utf8");
    const images = [...compose.matchAll(/image:\s*(quay\.io\/keycloak\/keycloak\S*)/g)].map(
      (match) => match[1],
    );
    expect(images).toHaveLength(2);
    for (const image of images) expect(image).toBe(keycloak);
  });
});

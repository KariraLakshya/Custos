import { createPublicKey, verify } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startTestOidcProvider, type TestOidcProvider } from "./oidc-provider.js";

let provider: TestOidcProvider;
beforeAll(async () => {
  provider = await startTestOidcProvider();
});
afterAll(() => provider.close());

async function idToken(): Promise<string> {
  const response = await fetch(`${provider.issuer}/token`, { method: "POST", body: "x" });
  return ((await response.json()) as { id_token: string }).id_token;
}

async function verifiesWithPublishedKey(token: string): Promise<boolean> {
  const { keys } = (await (await fetch(`${provider.issuer}/jwks`)).json()) as {
    keys: Record<string, unknown>[];
  };
  const [head, body, signature] = token.split(".") as [string, string, string];
  return verify(
    "sha256",
    Buffer.from(`${head}.${body}`),
    { key: createPublicKey({ key: keys[0]!, format: "jwk" }), dsaEncoding: "ieee-p1363" },
    Buffer.from(signature, "base64url"),
  );
}

describe("the in-test OIDC provider", () => {
  it("publishes discovery naming itself as issuer", async () => {
    const doc = (await (
      await fetch(`${provider.issuer}/.well-known/openid-configuration`)
    ).json()) as { issuer: string; token_endpoint: string };
    expect(doc.issuer).toBe(provider.issuer);
    expect(doc.token_endpoint).toBe(`${provider.issuer}/token`);
  });

  it("answers the token endpoint with the ID token set last, signed with its published key", async () => {
    provider.respondWith({ sub: "alice" });
    const token = await idToken();
    const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()) as {
      sub: string;
    };
    expect(payload.sub).toBe("alice");
    expect(await verifiesWithPublishedKey(token)).toBe(true);
  });

  it("signs with the impostor key when asked, which the published key does not verify", async () => {
    provider.respondWith({ sub: "mallory" }, provider.impostorKey);
    expect(await verifiesWithPublishedKey(await idToken())).toBe(false);
  });

  it("answers 404 to anything else", async () => {
    expect((await fetch(`${provider.issuer}/authorize`)).status).toBe(404);
  });
});

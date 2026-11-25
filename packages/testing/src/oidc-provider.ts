import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

/**
 * A minimal OIDC provider for tests of operator SSO (ADR 0010). A real
 * provider never issues the broken tokens the negative tests need (bad
 * signature, wrong issuer, audience or nonce, expired), so this one does,
 * signed with node:crypto (ES256). It serves discovery, its JWKS and a token
 * endpoint that answers with whatever ID token was set last. Never used
 * outside tests.
 */
export interface TestOidcProvider {
  /** `http://127.0.0.1:<port>`, as the discovery document states it. */
  readonly issuer: string;
  /** A key the provider does not publish: tokens it signs must be refused. */
  readonly impostorKey: KeyObject;
  /** The token endpoint's next ID token: `claims`, signed with `key` (default: the published key). */
  respondWith(claims: object, key?: KeyObject): void;
  close(): Promise<void>;
}

const b64 = (value: object | Buffer): string =>
  (Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value))).toString("base64url");

export async function startTestOidcProvider(): Promise<TestOidcProvider> {
  const signing = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const impostor = generateKeyPairSync("ec", { namedCurve: "P-256" });
  let issuer = "";
  let nextIdToken = "";

  const jwt = (claims: object, key: KeyObject): string => {
    const head = `${b64({ alg: "ES256", kid: "k1", typ: "JWT" })}.${b64(claims)}`;
    return `${head}.${b64(sign("sha256", Buffer.from(head), { key, dsaEncoding: "ieee-p1363" }))}`;
  };

  const server = createServer((req, res) => {
    const json = (body: unknown): void => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(body));
    };
    if (req.url === "/.well-known/openid-configuration") {
      return json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        code_challenge_methods_supported: ["S256"],
      });
    }
    if (req.url === "/jwks") {
      return json({
        keys: [
          { ...signing.publicKey.export({ format: "jwk" }), kid: "k1", alg: "ES256", use: "sig" },
        ],
      });
    }
    if (req.url === "/token" && req.method === "POST") {
      req.resume();
      req.on("end", () =>
        json({ access_token: "at", token_type: "Bearer", expires_in: 300, id_token: nextIdToken }),
      );
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    issuer,
    impostorKey: impostor.privateKey,
    respondWith(claims, key = signing.privateKey) {
      nextIdToken = jwt(claims, key);
    },
    close: () =>
      new Promise<void>((done, fail) => server.close((error) => (error ? fail(error) : done()))),
  };
}

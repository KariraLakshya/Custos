import { randomUUID } from "node:crypto";
import {
  buildHandOff,
  buildRegistrationRequest,
  buildTokenRequestProof,
  createLocalKeyProvider,
  handOffHash,
  createLocalSecretCipher,
  err,
  ok,
  type DelegatedGrant,
  type DelegationLimits,
  type SignedCredential,
} from "@custos/core";
import { buildServer as buildIdentityServer, createDb as createIdentityDb } from "@custos/identity";
import { bearer, createTestControlPlane } from "@custos/testing/control-plane";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { storeToolCredential } from "../credentials/store.js";
import { createDb } from "../db/client.js";
import { agentPolicies } from "../db/schema.js";
import { grantToolAccess } from "../policy/policy.js";
import { issueToolToken } from "./issue.js";
import { createInMemoryReplayCache, type ReplayCache } from "./replay-cache.js";
import { createTrustedIssuer, type TrustedIssuer } from "./trusted-issuer.js";

// ADR 0020 §4: a token request that carries a delegation chain.

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const vaultDb = createDb(databaseUrl);
const identityDb = createIdentityDb(databaseUrl);
const cipher = createLocalSecretCipher(new Uint8Array(32).fill(3));
const controlPlane = createTestControlPlane(identityDb);
const PORT = 4251;
const DOMAIN = `127.0.0.1:${PORT}`;
const TOKENS_URL = "https://vault.custos.example/tokens";
const MAX_SKEW = 60;
const LIMITS: DelegationLimits = {
  maxLinks: 3,
  maxLifetimeSeconds: 3600,
  maxBytes: 16_384,
  maxClockSkewSeconds: MAX_SKEW,
};
const OPERATOR = {
  kind: "operator",
  id: "key-ops",
  name: "alice@example.com",
  via: "sso",
} as const;
const ACTION = "query";

let nextStatusListIndex = 300_000;
const statusAllocator = {
  allocate: async () =>
    ok({
      statusListIndex: nextStatusListIndex++,
      statusListCredential: "http://127.0.0.1:4503/status/revocation",
    }),
};

interface Registered {
  readonly credential: SignedCredential;
  readonly did: string;
  readonly secretKey: Uint8Array;
}

let identity: Awaited<ReturnType<typeof buildIdentityServer>>;
let trustedIssuer: TrustedIssuer;
let operatorKey: string;
let a: Registered;
let b: Registered;
let c: Registered;
let tool: string;

async function register(): Promise<Registered> {
  const request = await buildRegistrationRequest({
    audience: `did:web:${encodeURIComponent(DOMAIN)}`,
    now: new Date(),
  });
  const response = await identity.inject({
    method: "POST",
    url: "/agents",
    headers: bearer(operatorKey),
    payload: request.body,
  });
  const body = response.json() as { credential: SignedCredential; did: string };
  return { credential: body.credential, did: body.did, secretKey: request.secretKey };
}

beforeAll(async () => {
  operatorKey = await controlPlane.key("operator", ["agents:register"]);
  identity = await buildIdentityServer({
    auditReporter: { report: () => {} },
    db: identityDb,
    controlPlaneAuth: controlPlane.guard,
    didDomain: DOMAIN,
    issuerKey: {
      keyProvider: createLocalKeyProvider({
        importedKeys: { issuer: new Uint8Array(32).fill(12) },
      }),
      keyId: "issuer",
    },
    statusAllocator,
  });
  await identity.listen({ port: PORT, host: "127.0.0.1" });
  trustedIssuer = createTrustedIssuer({ did: `did:web:127.0.0.1%3A${PORT}` });
  [a, b, c] = [await register(), await register(), await register()];
  tool = `test-tool-${randomUUID()}`;
  await storeToolCredential({ db: vaultDb, cipher, tool, secret: "sk_test_x" });
  // Only A holds the tool, granted by an operator: the root.
  await grantToolAccess(vaultDb, a.did, tool, OPERATOR);
});

afterAll(async () => {
  await identity.close();
  await vaultDb.$client.end();
  await identityDb.$client.end();
});

const grants = (actions: string[] = [ACTION], forTool = () => tool): DelegatedGrant[] => [
  { tool: forTool(), actions },
];

function handOff(
  from: Registered,
  to: Registered,
  options: {
    grants?: DelegatedGrant[];
    depth?: number;
    previous?: string;
    ttlSeconds?: number;
  } = {},
): string {
  return buildHandOff({
    from: from.did,
    to: to.did,
    grants: options.grants ?? grants(),
    depth: options.depth ?? 0,
    ...(options.previous === undefined ? {} : { previous: options.previous }),
    now: new Date(),
    ttlSeconds: options.ttlSeconds ?? 600,
    secretKey: from.secretKey,
  });
}

/** A revocation view that knows only agents it has been told about, like the real cache. */
function trackingView(revoked: ReadonlySet<string> = new Set()) {
  const known = new Set<string>();
  return {
    tracked: known,
    trackAgent: (did: string) => {
      known.add(did);
      return ok(undefined);
    },
    verdict: (did: string) =>
      !known.has(did)
        ? ("unknown" as const)
        : revoked.has(did)
          ? ("revoked" as const)
          : ("ok" as const),
  };
}

async function request(options: {
  requester: Registered;
  chain?: unknown;
  revocation?: ReturnType<typeof trackingView> | Parameters<typeof issueToolToken>[0]["revocation"];
  replayCache?: ReplayCache;
  proof?: string;
  action?: string;
  forTool?: string;
}) {
  const now = new Date();
  const forTool = options.forTool ?? tool;
  const action = options.action ?? ACTION;
  const signing = createLocalKeyProvider();
  const { keyId } = await signing.createKeyPair();
  return issueToolToken({
    db: vaultDb,
    keyProvider: signing,
    signingKeyId: keyId,
    agentCredential: options.requester.credential,
    tool: forTool,
    action,
    now,
    revocation: options.revocation ?? trackingView(),
    trustedIssuer,
    proofOfPossession: {
      proof:
        options.proof ??
        (await buildTokenRequestProof({
          audience: TOKENS_URL,
          secretKey: options.requester.secretKey,
          now,
          request: { tool: forTool, action },
        })),
      audience: TOKENS_URL,
      maxSkewSeconds: MAX_SKEW,
      replayCache: options.replayCache ?? createInMemoryReplayCache(),
    },
    ...(options.chain === undefined
      ? {}
      : { delegation: { chain: options.chain, limits: LIMITS } }),
  });
}

function claimsOf(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[0]!, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
}

describe("issueToolToken with a delegation chain", () => {
  it("issues B a token for A's tool, naming the chain, with no grant of B's own", async () => {
    const h = handOff(a, b);
    const chain = { handOffs: [h], credentials: [a.credential] };
    const result = await request({ requester: b, chain });
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    const claims = claimsOf(result.value.token);
    // `dref` links every call's audit entry to the issuance entry (ADR 0020 §6).
    expect(claims).toMatchObject({
      sub: b.did,
      tool,
      action: ACTION,
      chain: [a.did, b.did],
      dref: handOffHash(h),
    });
    expect(result.value.delegation).toEqual({
      agentId: b.did,
      chain: [a.did, b.did],
      root: OPERATOR,
      handOffs: [h],
      credentials: [a.credential],
      ref: handOffHash(h),
      checkedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
    });
    // Without the chain, B has no grant.
    const alone = await request({ requester: b });
    expect(!alone.ok && alone.error.code).toBe("POLICY_DENIED");
  });

  it("issues through two hand-offs that narrow", async () => {
    const first = handOff(a, b, { grants: grants([ACTION, "write"]), depth: 1 });
    const second = handOff(b, c, { previous: first });
    const result = await request({
      requester: c,
      chain: { handOffs: [first, second], credentials: [a.credential, b.credential] },
    });
    expect(result.ok && claimsOf(result.value.token).chain).toEqual([a.did, b.did, c.did]);
    // The reference is the last hand-off's, which commits to the first.
    expect(result.ok && claimsOf(result.value.token).dref).toBe(handOffHash(second));
  });

  it("makes every delegator known to the revocation view, so one that never asked for a token is not 'unknown'", async () => {
    const view = trackingView();
    const result = await request({
      requester: b,
      chain: { handOffs: [handOff(a, b)], credentials: [a.credential] },
      revocation: view,
    });
    expect(result.ok).toBe(true);
    expect([...view.tracked].sort()).toEqual([a.did, b.did].sort());
  });

  it("never lets the token outlive the hand-off", async () => {
    const result = await request({
      requester: b,
      chain: { handOffs: [handOff(a, b, { ttlSeconds: 20 })], credentials: [a.credential] },
    });
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    const claims = claimsOf(result.value.token) as { iat: number; exp: number };
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(20);
    expect(claims.exp - claims.iat).toBeGreaterThanOrEqual(19);
  });

  it("refuses when the delegator is revoked, naming the requester and the revoked agent", async () => {
    const result = await request({
      requester: b,
      chain: { handOffs: [handOff(a, b)], credentials: [a.credential] },
      revocation: trackingView(new Set([a.did])),
    });
    expect(result).toEqual(err({ code: "AGENT_REVOKED", agentId: b.did, revokedDid: a.did }));
  });

  it("refuses a revoked requester before looking at its chain's revocation", async () => {
    const result = await request({
      requester: b,
      chain: { handOffs: [handOff(a, b)], credentials: [a.credential] },
      revocation: trackingView(new Set([b.did])),
    });
    expect(result).toEqual(err({ code: "AGENT_REVOKED", agentId: b.did }));
  });

  it("refuses a delegator whose status entry cannot be tracked", async () => {
    const view = {
      trackAgent: (did: string) => (did === a.did ? err({ reason: "bad entry" }) : ok(undefined)),
      verdict: () => "ok" as const,
    };
    const result = await request({
      requester: b,
      chain: { handOffs: [handOff(a, b)], credentials: [a.credential] },
      revocation: view,
    });
    expect(result).toEqual(
      err({ code: "DELEGATION_DENIED", agentId: b.did, reason: "DELEGATOR_STATUS_INVALID" }),
    );
  });

  it("refuses a chain whose first delegator holds no operator grant for the tool", async () => {
    // C holds nothing; C hands to B.
    const fromC = await request({
      requester: b,
      chain: { handOffs: [handOff(c, b)], credentials: [c.credential] },
    });
    expect(fromC).toEqual(
      err({ code: "DELEGATION_DENIED", agentId: b.did, reason: "NO_ROOT_GRANT" }),
    );

    // A grant from before migration 0013 works for C itself, but is no root.
    await vaultDb.insert(agentPolicies).values({ agentDid: c.did, tool });
    expect((await request({ requester: c })).ok).toBe(true);
    const legacy = await request({
      requester: b,
      chain: { handOffs: [handOff(c, b)], credentials: [c.credential] },
    });
    expect(legacy).toEqual(
      err({ code: "DELEGATION_DENIED", agentId: b.did, reason: "NO_ROOT_GRANT" }),
    );
  });

  it("refuses a widened chain without using up the proof, which then works with a valid chain", async () => {
    const replayCache = createInMemoryReplayCache();
    const now = new Date();
    const proof = await buildTokenRequestProof({
      audience: TOKENS_URL,
      secretKey: c.secretKey,
      now,
      request: { tool, action: ACTION },
    });
    const first = handOff(a, b, { depth: 1, grants: grants(["write"]) });
    // B hands on an action it was not given.
    const widened = handOff(b, c, { previous: first, grants: grants([ACTION]) });
    const refused = await request({
      requester: c,
      chain: { handOffs: [first, widened], credentials: [a.credential, b.credential] },
      replayCache,
      proof,
    });
    expect(refused).toEqual(err({ code: "DELEGATION_DENIED", agentId: c.did, reason: "WIDENED" }));

    const goodFirst = handOff(a, b, { depth: 1 });
    const good = handOff(b, c, { previous: goodFirst });
    const accepted = await request({
      requester: c,
      chain: { handOffs: [goodFirst, good], credentials: [a.credential, b.credential] },
      replayCache,
      proof,
    });
    expect(accepted.ok).toBe(true);
  });

  it("refuses a forged hand-off, and a prefix presented by someone other than its holder", async () => {
    // Claims to be from A, signed with C's key.
    const forged = buildHandOff({
      from: a.did,
      to: b.did,
      grants: grants(),
      depth: 0,
      now: new Date(),
      ttlSeconds: 600,
      secretKey: c.secretKey,
    });
    expect(
      await request({ requester: b, chain: { handOffs: [forged], credentials: [a.credential] } }),
    ).toEqual(err({ code: "DELEGATION_DENIED", agentId: b.did, reason: "SIGNATURE_INVALID" }));

    expect(
      await request({
        requester: c,
        chain: { handOffs: [handOff(a, b)], credentials: [a.credential] },
      }),
    ).toEqual(err({ code: "DELEGATION_DENIED", agentId: c.did, reason: "WRONG_HOLDER" }));
  });

  it("refuses a sub-agent asking for an action its delegator was not given", async () => {
    const result = await request({
      requester: b,
      chain: { handOffs: [handOff(a, b)], credentials: [a.credential] },
      action: "write",
    });
    expect(result).toEqual(
      err({ code: "DELEGATION_DENIED", agentId: b.did, reason: "NOT_COVERED" }),
    );
  });
});

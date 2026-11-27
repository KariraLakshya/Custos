// Records the dashboard's test fixtures (ADR 0022 §5; docs/dashboard-plan.md
// "How it is tested"): a real sealed audit log, in four versions (clean,
// tampered, truncated, delegated), with the GET /agents, GET /policies and
// GET /revocations answers that go with it.
//
// Regenerate with:  pnpm --filter @custos/dashboard fixtures
// (after `pnpm build`, since it imports @custos/core's built output). The run
// is reproducible: every key comes from a fixed seed and every time from a
// fixed clock, so running it twice writes the same bytes.
//
// TEST KEYS ONLY. Each seed is the SHA-256 of a readable label saying so.
// They sign nothing but these fixtures and must never be used anywhere else.
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildHandOff,
  buildStatusListEntry,
  computeAuditEntryHash,
  computeAuditPayloadHash,
  handOffHash,
  issueAuditSeal,
  issueCredential,
  issueRevocationTombstone,
  pinnedDidDocument,
  publicKeyFromSecretKey,
  publicKeyToMultibase,
  serializeAuditRecord,
  sign,
  AUDIT_GENESIS_HASH,
} from "@custos/core";

const OUT = join(dirname(dirname(fileURLToPath(import.meta.url))), "fixtures");

/** A test key pair from a readable label: never a secret, never used outside fixtures. */
function testKey(label) {
  const secretKey = createHash("sha256")
    .update(`custos dashboard fixtures: TEST KEY, not a secret: ${label}`)
    .digest();
  return { secretKey: new Uint8Array(secretKey), publicKey: publicKeyFromSecretKey(secretKey) };
}

const signer = (keys) => ({ sign: (data) => Promise.resolve(sign(data, keys.secretKey)) });
const must = (result) => {
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.value;
};

// The fixed clock: the views are tested at NOW, a few minutes after the story.
const T0 = Date.parse("2026-11-20T14:00:00.000Z");
const at = (minutes, seconds = 0) => new Date(T0 + minutes * 60_000 + seconds * 1000);
const iso = (minutes, seconds = 0) => at(minutes, seconds).toISOString();
const NOW = iso(10);

const IDENTITY = "did:web:localhost%3A4001";
const REVOCATION = "did:web:localhost%3A4003";
const AUDIT = "did:web:localhost%3A4004";
const identityKeys = testKey("identity issuer");
const revocationKeys = testKey("revocation tombstones");
const auditKeys = testKey("audit seals");

const ALICE = { kind: "operator", id: "0a1b2c3d4e5f6071", name: "alice@company.com" };
const ALICE_SSO = { ...ALICE, via: "sso" };
const SERVICE = {
  identity: { kind: "service", id: "1d00000000000001", name: "identity" },
  vault: { kind: "service", id: "1d00000000000002", name: "vault" },
  revocation: { kind: "service", id: "1d00000000000003", name: "revocation" },
};

const BILLING = {
  id: "6f1d2c3b-0000-4000-8000-00000000a1b2",
  name: "billing-bot",
  keys: testKey("agent billing-bot"),
  index: 0,
};
const HELPER = {
  id: "6f1d2c3b-0000-4000-8000-00000000c3d4",
  name: "helper-bot",
  keys: testKey("agent helper-bot"),
  index: 1,
};
for (const agent of [BILLING, HELPER]) agent.did = `${IDENTITY}:agents:${agent.id}`;

// --- audit events, as the services report them --------------------------

const control = (principal, action, scope, agentDid, extra = {}) => ({
  principal,
  authorityChain: [],
  ...(agentDid === undefined ? {} : { agentDid }),
  action,
  dataCategories: [],
  policy: { rule: `control-plane-scope:${scope}`, decision: "allow" },
  ...extra,
});
const call = (agent, tool, action, rule, decision, extra = {}) => ({
  agentDid: agent.did,
  authorityChain: [agent.did],
  tool,
  action,
  // Only a call that reached the connector names its categories (vault `invoke.ts`).
  dataCategories: decision === "allow" && tool === "mock-database" ? ["internal-records"] : [],
  policy: { rule, decision },
  ...extra,
});
const register = (agent, minute) => [
  {
    event: control(SERVICE.identity, "status.allocate", "status:allocate", agent.did),
    reportedBy: SERVICE.revocation,
    minute,
  },
  {
    event: control(ALICE, "agents.register", "agents:register", agent.did),
    reportedBy: SERVICE.identity,
    minute,
    seconds: 1,
  },
];
const grant = (agent, tool, minute) => ({
  event: control(ALICE, "policies.grant", "policies:write", agent.did, { tool }),
  reportedBy: SERVICE.vault,
  minute,
});

/** The record exactly as the audit service builds it, field for field (`append.ts`). */
function stored({ event, reportedBy, minute, seconds = 0 }) {
  return {
    ...(event.agentDid === undefined ? {} : { agentDid: event.agentDid }),
    ...(event.principal === undefined ? {} : { principal: event.principal }),
    authorityChain: event.authorityChain,
    ...(event.tool === undefined ? {} : { tool: event.tool }),
    action: event.action,
    dataCategories: event.dataCategories,
    policy: event.policy,
    ...(event.reason === undefined ? {} : { reason: event.reason }),
    recordedAt: iso(minute, seconds),
    reportedBy,
    ...(event.delegationRef === undefined ? {} : { delegationRef: event.delegationRef }),
    ...(event.delegation === undefined ? {} : { delegation: event.delegation }),
  };
}

// --- the ledger as served -------------------------------------------------

async function seal(log, entries, sealSeq, sealedAtMinute) {
  let prevHash = AUDIT_GENESIS_HASH;
  let headHash;
  entries.forEach((entry) => {
    prevHash = computeAuditEntryHash({ seq: entry.seq, prevHash, payloadHash: entry.payloadHash });
    if (entry.seq === sealSeq) headHash = prevHash;
  });
  return must(
    await issueAuditSeal({
      seal: {
        log,
        seq: sealSeq,
        headHash,
        key: publicKeyToMultibase(auditKeys.publicKey),
        sealedAt: iso(sealedAtMinute),
      },
      signer: signer(auditKeys),
    }),
  );
}

function chainEntries(records) {
  return records.map((record, i) => {
    const payload = serializeAuditRecord(record);
    return { seq: i + 1, payloadHash: computeAuditPayloadHash(payload), payload };
  });
}

// --- the other services' answers --------------------------------------------

const agentsAnswer = (agents) => ({
  agents: agents.map((agent) => ({
    id: agent.id,
    did: agent.did,
    name: agent.name,
    registeredAt: iso(agent.registeredMinute),
    registeredBy: ALICE_SSO,
  })),
  nextCursor: null,
});

const policiesAnswer = (grants) => ({
  grants: grants.map(([agent, tool, minute]) => ({
    agentDid: agent.did,
    tool,
    grantedBy: ALICE_SSO,
    createdAt: iso(minute),
  })),
  nextCursor: null,
});

async function revocationsAnswer(revoked) {
  const tombstones = [];
  for (const [agent, minute, reason] of revoked) {
    tombstones.push(
      must(
        await issueRevocationTombstone({
          tombstone: {
            agentDid: agent.did,
            statusListIndex: agent.index,
            revokedAt: iso(minute),
            reason,
          },
          signer: signer(revocationKeys),
        }),
      ),
    );
  }
  return { tombstones, asOf: NOW };
}

// --- a credential for the delegated story (JSON-LD, Ed25519Signature2020) ---

/** jsonld-signatures stamps `proof.created` with `new Date()`; pin it to the fixed clock. */
async function withFixedClock(time, run) {
  const RealDate = globalThis.Date;
  class FixedDate extends RealDate {
    constructor(...args) {
      super(...(args.length === 0 ? [time] : args));
    }
    static now() {
      return time;
    }
  }
  globalThis.Date = FixedDate;
  try {
    return await run();
  } finally {
    globalThis.Date = RealDate;
  }
}

async function credentialFor(agent, minute) {
  return withFixedClock(at(minute).getTime(), async () =>
    must(
      await issueCredential({
        unsignedCredential: {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            {
              publicKeyMultibase: {
                "@id": "https://w3id.org/security#publicKeyMultibase",
                "@type": "https://w3id.org/security#multibase",
              },
            },
          ],
          id: `urn:uuid:${agent.id}`,
          type: ["VerifiableCredential"],
          issuer: IDENTITY,
          validFrom: iso(minute),
          credentialSubject: {
            id: agent.did,
            publicKeyMultibase: publicKeyToMultibase(agent.keys.publicKey),
          },
          credentialStatus: buildStatusListEntry({
            statusListCredential: "http://localhost:4003/status/revocation",
            statusListIndex: agent.index,
          }),
        },
        signer: {
          id: `${IDENTITY}#${publicKeyToMultibase(identityKeys.publicKey)}`,
          sign: ({ data }) => Promise.resolve(sign(data, identityKeys.secretKey)),
        },
      }),
    ),
  );
}

// --- the four versions ----------------------------------------------------

const documents = {
  audit: pinnedDidDocument(AUDIT, auditKeys.publicKey),
  identity: pinnedDidDocument(IDENTITY, identityKeys.publicKey),
  revocation: pinnedDidDocument(REVOCATION, revocationKeys.publicKey),
};

function fixture(name, description, parts) {
  return {
    name,
    description,
    note: "Recorded by apps/dashboard/scripts/record-fixtures.mjs with TEST KEYS from fixed seeds and a fixed clock. Not secrets; never use these keys elsewhere.",
    now: NOW,
    auditDid: AUDIT,
    identityDid: IDENTITY,
    revocationDid: REVOCATION,
    didDocuments: documents,
    ...parts,
  };
}

// The clean story: user-journey moments 3 to 7.
const cleanEvents = [
  ...register(BILLING, 0),
  grant(BILLING, "mock-database", 1),
  {
    event: call(BILLING, "mock-database", "query", "scoped-token", "allow"),
    reportedBy: SERVICE.vault,
    minute: 2,
  },
  {
    event: call(BILLING, "stripe", "list-customers", "agent-tool-allowlist", "deny", {
      reason: "no policy grant for this agent/tool pair",
    }),
    reportedBy: SERVICE.vault,
    minute: 3,
  },
  {
    event: control(ALICE, "agents.revoke", "agents:revoke", BILLING.did, { reason: "key leaked" }),
    reportedBy: SERVICE.revocation,
    minute: 5,
  },
  {
    event: call(BILLING, "mock-database", "query", "revocation", "deny", {
      reason: "agent is revoked",
    }),
    reportedBy: SERVICE.vault,
    minute: 6,
  },
];
const cleanEntries = chainEntries(cleanEvents.map(stored));
// Sealed through the cut-off; the refusal after it is not sealed yet.
const cleanSeal = await seal(AUDIT, cleanEntries, 6, 5);
const billingOnly = { ...BILLING, registeredMinute: 0 };
const cleanServices = {
  agents: agentsAnswer([billingOnly]),
  policies: policiesAnswer([[BILLING, "mock-database", 1]]),
  revocations: await revocationsAnswer([[BILLING, 5, "key leaked"]]),
};

const clean = fixture(
  "clean",
  "billing-bot registered, granted mock-database, one allowed call, one refusal, cut off, one refusal after.",
  { audit: { entries: cleanEntries, seal: cleanSeal }, ...cleanServices },
);

// Tampered: entry 4 (the allowed call) rewritten after it was sealed, its
// stored hash left as it was. The seal and every other entry are untouched.
const tamperedEntries = cleanEntries.map((entry) =>
  entry.seq === 4
    ? { ...entry, payload: entry.payload.replace('"mock-database"', '"stripe"') }
    : entry,
);
const tampered = fixture(
  "tampered",
  "The clean log with entry 4's contents edited after it was sealed (PAYLOAD_MISMATCH).",
  { audit: { entries: tamperedEntries, seal: cleanSeal }, ...cleanServices },
);

// Truncated: the newest entries deleted; the seal still covers entry 6.
const truncated = fixture(
  "truncated",
  "The clean log with entries 6 and 7 deleted; its seal still covers entry 6 (TRUNCATED).",
  { audit: { entries: cleanEntries.slice(0, 5), seal: cleanSeal }, ...cleanServices },
);

// Delegated: alice → billing-bot → helper-bot, used once (ADR 0020 §6).
const billingCredential = await credentialFor(BILLING, 0);
const handOff = buildHandOff({
  from: BILLING.did,
  to: HELPER.did,
  grants: [{ tool: "mock-database", actions: ["query"] }],
  depth: 0,
  now: at(4),
  ttlSeconds: 3600,
  secretKey: BILLING.keys.secretKey,
  jti: "6f1d2c3b-0000-4000-8000-0000000000d1",
});
const ref = handOffHash(handOff);
const delegatedCall = (extra) =>
  call(HELPER, "mock-database", "query", "delegation:mock-database", "allow", {
    authorityChain: [BILLING.did, HELPER.did],
    delegationRef: ref,
    ...extra,
  });
const delegatedEvents = [
  ...register(BILLING, 0),
  grant(BILLING, "mock-database", 1),
  ...register(HELPER, 2),
  {
    event: delegatedCall({
      reason: "token issued under delegation",
      delegation: {
        root: ALICE_SSO,
        handOffs: [handOff],
        credentials: [billingCredential],
        checkedAt: iso(5),
      },
    }),
    reportedBy: SERVICE.vault,
    minute: 5,
  },
  { event: delegatedCall({}), reportedBy: SERVICE.vault, minute: 5, seconds: 1 },
];
const delegatedEntries = chainEntries(delegatedEvents.map(stored));
const delegated = fixture(
  "delegated",
  "billing-bot passes mock-database query to helper-bot; helper-bot uses it once. Chain: alice@company.com → billing-bot → helper-bot.",
  {
    audit: {
      entries: delegatedEntries,
      seal: await seal(AUDIT, delegatedEntries, delegatedEntries.length, 6),
    },
    agents: agentsAnswer([billingOnly, { ...HELPER, registeredMinute: 2 }]),
    policies: policiesAnswer([[BILLING, "mock-database", 1]]),
    revocations: await revocationsAnswer([]),
  },
);

mkdirSync(OUT, { recursive: true });
for (const recorded of [clean, tampered, truncated, delegated]) {
  writeFileSync(join(OUT, `${recorded.name}.json`), `${JSON.stringify(recorded, null, 2)}\n`);
}
console.log(`wrote 4 fixtures to ${OUT}`);

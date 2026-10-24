// Test fixtures: a foreign organisation ("A") with its own identity and status
// keys, the agents it issued, and signed status lists. Not exported.
import {
  buildForeignCallProof,
  buildStatusListEntry,
  createStatusList,
  generateKeyPair,
  issueCredential,
  issueStatusListCredential,
  publicKeyToMultibase,
  setRevoked,
  sign,
  type SignedCredential,
} from "@custos/core";
import type { ConfiguredAnchor } from "./anchors.js";

export const NOW = new Date("2026-10-22T12:00:00.000Z");
export const STATUS_LIST_ID = "https://a.example/status/revocation";
export const STATUS_FETCH_URL = "https://a.example/status/revocation";
export const RECEIVER = "https://b.example/federation";

const SECURITY = "https://w3id.org/security#";
const AGENT_KEY_CONTEXT = {
  publicKeyMultibase: { "@id": `${SECURITY}publicKeyMultibase`, "@type": `${SECURITY}multibase` },
} as const;

interface KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export interface Organisation {
  readonly identityDid: string;
  readonly identityKeys: KeyPair;
  readonly statusDid: string;
  readonly statusKeys: KeyPair;
  readonly anchor: ConfiguredAnchor;
}

export function makeOrganisation(overrides: Partial<ConfiguredAnchor> = {}): Organisation {
  const identityKeys = generateKeyPair();
  const statusKeys = generateKeyPair();
  const identityDid = "did:web:a.example";
  const statusDid = "did:web:a.example:revocation";
  return {
    identityDid,
    identityKeys,
    statusDid,
    statusKeys,
    anchor: {
      domain: "a.example",
      credentialIssuerDid: identityDid,
      credentialIssuerPublicKey: identityKeys.publicKey,
      statusIssuerDid: statusDid,
      statusIssuerPublicKey: statusKeys.publicKey,
      statusListId: STATUS_LIST_ID,
      statusFetchUrl: STATUS_FETCH_URL,
      maxStatusAgeSeconds: 3600,
      enabled: true,
      ...overrides,
    },
  };
}

function signerFor(did: string, keys: KeyPair) {
  return {
    id: `${did}#${publicKeyToMultibase(keys.publicKey)}`,
    sign: ({ data }: { data: Uint8Array }) => Promise.resolve(sign(data, keys.secretKey)),
  };
}

export interface Agent {
  readonly credential: SignedCredential;
  readonly keys: KeyPair;
  readonly did: string;
}

export async function issueAgent(
  org: Organisation,
  options: { index?: number; noStatus?: boolean } = {},
): Promise<Agent> {
  const keys = generateKeyPair();
  const did = `${org.identityDid}:agents:${crypto.randomUUID()}`;
  const issued = await issueCredential({
    unsignedCredential: {
      "@context": ["https://www.w3.org/ns/credentials/v2", AGENT_KEY_CONTEXT],
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: ["VerifiableCredential"],
      issuer: org.identityDid,
      validFrom: new Date(NOW.getTime() - 60_000).toISOString(),
      credentialSubject: { id: did, publicKeyMultibase: publicKeyToMultibase(keys.publicKey) },
      ...(options.noStatus === true
        ? {}
        : {
            credentialStatus: buildStatusListEntry({
              statusListCredential: STATUS_LIST_ID,
              statusListIndex: options.index ?? 7,
            }),
          }),
    },
    signer: signerFor(org.identityDid, org.identityKeys),
  });
  if (!issued.ok) throw new Error(issued.error.reason);
  return { credential: issued.value, keys, did };
}

export async function issueList(
  org: Organisation,
  options: {
    revoked?: readonly number[];
    now?: Date;
    validForMs?: number;
    signWith?: KeyPair;
  } = {},
): Promise<SignedCredential> {
  let list = createStatusList();
  for (const index of options.revoked ?? []) {
    const next = setRevoked(list, index, true);
    if (!next.ok) throw new Error("fixture index out of range");
    list = next.value;
  }
  const now = options.now ?? NOW;
  const issued = await issueStatusListCredential({
    list,
    issuerDid: org.statusDid,
    signer: signerFor(org.statusDid, options.signWith ?? org.statusKeys),
    statusListCredentialUrl: org.anchor.statusListId,
    now,
    validUntil: new Date(now.getTime() + (options.validForMs ?? 1_800_000)),
  });
  if (!issued.ok) throw new Error(issued.error.reason);
  return issued.value;
}

/** The request the fixtures sign by default, and the gate is asked to run. */
export const REQUEST = { tool: "b-ledger", action: "read" } as const;

export function proofFor(
  agent: Agent,
  overrides: { now?: Date; jti?: string; request?: { tool: string; action: string } } = {},
): Promise<string> {
  return buildForeignCallProof({
    audience: RECEIVER,
    request: overrides.request ?? REQUEST,
    secretKey: agent.keys.secretKey,
    now: overrides.now ?? NOW,
    ...(overrides.jti === undefined ? {} : { jti: overrides.jti }),
  });
}

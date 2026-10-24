// Test fixtures for the federation tests: a foreign organisation ("A") with its
// own identity key and status key, agents it has issued, and signed status lists.
// Not exported from the package.
import { generateKeyPair, sign } from "../crypto/ed25519.js";
import { publicKeyToMultibase } from "../did/did-web.js";
import { buildForeignCallProof } from "../proof/possession.js";
import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  buildStatusListEntry,
  buildStatusListSubject,
  createStatusList,
  setRevoked,
} from "../status/bitstring-status-list.js";
import { issueCredential, type SignedCredential } from "../vc/credential.js";
import type { ForeignReplayGuard, ReplayVerdict } from "./verify-agent.js";
import type { TrustAnchor } from "./trust-anchor.js";

/** A credential as plain editable JSON, for tamper tests. */
export type Draft = { [key: string]: unknown };
export const sub = (draft: Draft): Draft => draft.credentialSubject as Draft;
export const stat = (draft: Draft): Draft => draft.credentialStatus as Draft;

export const NOW = new Date("2026-10-17T12:00:00.000Z");
export const STATUS_LIST_ID = "https://a.example/status/revocation";
export const RECEIVER = "https://b.example/federation";
/** The one request the fixtures sign and the verifier expects, so the two cannot drift. */
export const REQUEST = { tool: "b-ledger", action: "read" } as const;
const SECURITY = "https://w3id.org/security#";
const AGENT_KEY_CONTEXT = {
  publicKeyMultibase: { "@id": `${SECURITY}publicKeyMultibase`, "@type": `${SECURITY}multibase` },
} as const;

export interface KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export interface Organisation {
  readonly identityDid: string;
  readonly identityKeys: KeyPair;
  readonly statusDid: string;
  readonly statusKeys: KeyPair;
  readonly anchor: TrustAnchor;
}

export function makeOrganisation(overrides: Partial<TrustAnchor> = {}): Organisation {
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
      maxStatusAgeSeconds: 3600,
      enabled: true,
      ...overrides,
    },
  };
}

async function sign2(
  did: string,
  keys: KeyPair,
  unsigned: Parameters<typeof issueCredential>[0]["unsignedCredential"],
): Promise<SignedCredential> {
  const issued = await issueCredential({
    unsignedCredential: unsigned,
    signer: {
      id: `${did}#${publicKeyToMultibase(keys.publicKey)}`,
      sign: ({ data }) => Promise.resolve(sign(data, keys.secretKey)),
    },
  });
  if (!issued.ok) throw new Error(issued.error.reason);
  return issued.value;
}

export interface AgentOptions {
  readonly index?: number;
  readonly validFrom?: Date;
  readonly validUntil?: string;
  readonly noStatus?: boolean;
  readonly statusListCredential?: string;
  readonly statusListIndexText?: string;
  /** Sign with this key instead of the organisation's identity key. */
  readonly signWith?: KeyPair;
  readonly issuerDid?: string;
}

export interface Agent {
  readonly credential: SignedCredential;
  readonly keys: KeyPair;
  readonly did: string;
}

export async function issueAgent(org: Organisation, options: AgentOptions = {}): Promise<Agent> {
  const keys = generateKeyPair();
  const did = `did:web:a.example:agents:${crypto.randomUUID()}`;
  const index = options.index ?? 7;
  const entry = buildStatusListEntry({
    statusListCredential: STATUS_LIST_ID,
    statusListIndex: index,
  });
  const credentialStatus = {
    ...entry,
    ...(options.statusListCredential === undefined
      ? {}
      : { statusListCredential: options.statusListCredential }),
    ...(options.statusListIndexText === undefined
      ? {}
      : { statusListIndex: options.statusListIndexText }),
  };
  const credential = await sign2(org.identityDid, options.signWith ?? org.identityKeys, {
    "@context": ["https://www.w3.org/ns/credentials/v2", AGENT_KEY_CONTEXT],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential"],
    issuer: options.issuerDid ?? org.identityDid,
    validFrom: (options.validFrom ?? new Date(NOW.getTime() - 60_000)).toISOString(),
    ...(options.validUntil === undefined ? {} : { validUntil: options.validUntil }),
    credentialSubject: { id: did, publicKeyMultibase: publicKeyToMultibase(keys.publicKey) },
    ...(options.noStatus === true ? {} : { credentialStatus }),
  });
  return { credential, keys, did };
}

export interface CustomAgentFields {
  readonly validFrom?: string;
  readonly validUntil?: string;
  readonly subject?: Record<string, unknown>;
  readonly credentialStatus?: Record<string, unknown> | null;
}

/**
 * A credential genuinely signed by the organisation's identity key whose fields
 * are chosen freely, to reach checks that only apply to correctly signed input.
 */
export async function issueCustomAgent(
  org: Organisation,
  agent: Agent,
  fields: CustomAgentFields,
): Promise<SignedCredential> {
  const status =
    fields.credentialStatus === undefined
      ? buildStatusListEntry({ statusListCredential: STATUS_LIST_ID, statusListIndex: 7 })
      : fields.credentialStatus;
  return sign2(org.identityDid, org.identityKeys, {
    "@context": ["https://www.w3.org/ns/credentials/v2", AGENT_KEY_CONTEXT],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential"],
    issuer: org.identityDid,
    validFrom: fields.validFrom ?? new Date(NOW.getTime() - 60_000).toISOString(),
    ...(fields.validUntil === undefined ? {} : { validUntil: fields.validUntil }),
    credentialSubject: fields.subject ?? {
      id: agent.did,
      publicKeyMultibase: publicKeyToMultibase(agent.keys.publicKey),
    },
    ...(status === null ? {} : { credentialStatus: status as never }),
  });
}

export interface ListOptions {
  readonly revoked?: readonly number[];
  readonly validFrom?: Date;
  readonly validUntil?: Date | null;
  readonly signWith?: KeyPair;
  readonly id?: string;
  readonly purpose?: "revocation" | "suspension";
  readonly types?: readonly string[];
}

export async function issueList(
  org: Organisation,
  options: ListOptions = {},
): Promise<SignedCredential> {
  let list = createStatusList();
  for (const index of options.revoked ?? []) {
    const next = setRevoked(list, index, true);
    if (!next.ok) throw new Error("fixture index out of range");
    list = next.value;
  }
  const validFrom = options.validFrom ?? new Date(NOW.getTime() - 10_000);
  const validUntil =
    options.validUntil === null
      ? undefined
      : (options.validUntil ?? new Date(validFrom.getTime() + 1_800_000));
  const id = options.id ?? STATUS_LIST_ID;
  return sign2(org.statusDid, options.signWith ?? org.statusKeys, {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id,
    type: [...(options.types ?? ["VerifiableCredential", BITSTRING_STATUS_LIST_CREDENTIAL_TYPE])],
    issuer: org.statusDid,
    validFrom: validFrom.toISOString(),
    ...(validUntil === undefined ? {} : { validUntil: validUntil.toISOString() }),
    credentialSubject: {
      ...buildStatusListSubject({
        id: `${id}#list`,
        list,
        ...(options.purpose === undefined ? {} : { statusPurpose: options.purpose }),
      }),
    },
  });
}

export function proofFor(
  agent: Agent,
  overrides: {
    audience?: string;
    now?: Date;
    jti?: string;
    secretKey?: Uint8Array;
    request?: { tool: string; action: string };
  } = {},
): Promise<string> {
  return buildForeignCallProof({
    audience: overrides.audience ?? RECEIVER,
    request: overrides.request ?? REQUEST,
    secretKey: overrides.secretKey ?? agent.keys.secretKey,
    now: overrides.now ?? NOW,
    ...(overrides.jti === undefined ? {} : { jti: overrides.jti }),
  });
}

/**
 * A guard with the same expiry rule as the vault's `ReplayCache`: an entry counts
 * as a replay while `expiresAtMs >= nowMs`, and is forgotten after that.
 */
export function expiringReplayGuard(): ForeignReplayGuard {
  const expiries = new Map<string, number>();
  return {
    record(key, expiresAtMs, nowMs): ReplayVerdict {
      const existing = expiries.get(key);
      if (existing !== undefined && existing >= nowMs) return "replayed";
      expiries.set(key, expiresAtMs);
      return "fresh";
    },
  };
}

export function memoryReplayGuard(
  options: { full?: boolean; async?: boolean } = {},
): ForeignReplayGuard & {
  readonly seen: string[];
} {
  const seen: string[] = [];
  return {
    seen,
    record(key): ReplayVerdict | Promise<ReplayVerdict> {
      const verdict: ReplayVerdict =
        options.full === true ? "full" : seen.includes(key) ? "replayed" : "fresh";
      if (verdict === "fresh") seen.push(key);
      return options.async === true ? Promise.resolve(verdict) : verdict;
    },
  };
}

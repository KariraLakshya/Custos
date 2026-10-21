// Test support for the publisher: a temporary directory, a fixed key and clock,
// and helpers to build agent credentials. Not part of the package's behaviour.
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildStatusListEntry,
  createLocalKeyProvider,
  generateKeyPair,
  issueCredential,
  publicKeyToMultibase,
  sign,
  statusListCredentialUrl,
  type SignedCredential,
} from "@custos/core";
import type { PublisherConfig, PublisherDeps } from "./publish.js";

/** Start a publisher in a test that does not have a host to ask. */
export const INIT = { init: true, acknowledgeNoPublishedList: true } as const;

export const T0 = new Date("2026-10-21T10:00:00.000Z");
export const DOMAIN = "a.example";
export const SEED = "11".repeat(32);

export function mutableClock(start = T0) {
  let now = start;
  return {
    now: () => now,
    set: (value: Date) => {
      now = value;
    },
    advance: (ms: number) => {
      now = new Date(now.getTime() + ms);
    },
  };
}

export function keyFor(seedHex: string) {
  return {
    keyProvider: createLocalKeyProvider({
      importedKeys: { publisher: Buffer.from(seedHex, "hex") },
    }),
    keyId: "publisher",
  };
}

export interface Kit {
  readonly dir: string;
  readonly config: PublisherConfig;
  readonly deps: PublisherDeps;
  readonly clock: ReturnType<typeof mutableClock>;
  readonly out: string;
  readonly cleanup: () => Promise<void>;
}

export async function makeKit(
  overrides: Partial<PublisherConfig> = {},
  depOverrides: Partial<PublisherDeps> = {},
): Promise<Kit> {
  const dir = await mkdtemp(join(tmpdir(), "custos-publisher-"));
  const clock = mutableClock();
  const out = join(dir, "site", "status.json");
  const config: PublisherConfig = {
    domain: DOMAIN,
    dir: join(dir, "publisher"),
    out,
    validitySeconds: 3600,
    stampSeconds: 1200,
    maxClockSkewSeconds: 5,
    lockWaitMs: 2_000,
    ...overrides,
  };
  return {
    dir,
    config,
    clock,
    out,
    deps: { ...keyFor(SEED), clock, ...depOverrides },
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

export async function readList(path: string): Promise<SignedCredential> {
  return JSON.parse(await readFile(path, "utf8")) as SignedCredential;
}

export const LIST_ID = statusListCredentialUrl(DOMAIN);

/** A genuine agent credential from A's identity service, as `register` saves it. */
export async function issueAgentCredential(params: {
  readonly identityDid: string;
  readonly identityKeys: { publicKey: Uint8Array; secretKey: Uint8Array };
  readonly index: number;
  readonly statusListCredential?: string;
  readonly noStatus?: boolean;
  readonly agentDid?: string;
}): Promise<SignedCredential> {
  const agentKeys = generateKeyPair();
  const SECURITY = "https://w3id.org/security#";
  const issued = await issueCredential({
    unsignedCredential: {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {
          publicKeyMultibase: {
            "@id": `${SECURITY}publicKeyMultibase`,
            "@type": `${SECURITY}multibase`,
          },
        },
      ],
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: ["VerifiableCredential"],
      issuer: params.identityDid,
      validFrom: new Date(T0.getTime() - 60_000).toISOString(),
      credentialSubject: {
        id: params.agentDid ?? `${params.identityDid}:agents:${crypto.randomUUID()}`,
        publicKeyMultibase: publicKeyToMultibase(agentKeys.publicKey),
      },
      ...(params.noStatus === true
        ? {}
        : {
            credentialStatus: buildStatusListEntry({
              statusListCredential: params.statusListCredential ?? LIST_ID,
              statusListIndex: params.index,
            }),
          }),
    },
    signer: {
      id: `${params.identityDid}#${publicKeyToMultibase(params.identityKeys.publicKey)}`,
      sign: ({ data }) => Promise.resolve(sign(data, params.identityKeys.secretKey)),
    },
  });
  if (!issued.ok) throw new Error(issued.error.reason);
  return issued.value;
}

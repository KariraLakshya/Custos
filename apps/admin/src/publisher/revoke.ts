import { readFile } from "node:fs/promises";
import {
  multibaseToPublicKey,
  pinnedDidDocument,
  statusListCredentialUrl,
  verifyCredential,
  type SignedCredential,
} from "@custos/core";
import { appendJournal, parseStatusIndex } from "./journal.js";
import {
  hasBaseline,
  publisherPaths,
  publishOnce,
  type PublishError,
  type PublisherConfig,
  type PublisherDeps,
  type PublishOutcome,
} from "./publish.js";

/** Who to revoke: an agent's credential (preferred), or a raw index typed twice. */
export type RevokeTarget =
  { readonly credentialPath: string } | { readonly index: string; readonly confirmIndex: string };

/** A's identity service, pinned: what makes a credential file proof of a real agent. */
export interface PinnedIdentity {
  readonly did: string;
  /** Multibase public key, as shown in A's DID document. */
  readonly publicKeyMultibase: string;
}

export type RevokeError =
  | PublishError
  | { readonly code: "INVALID_TARGET"; readonly reason: string }
  | { readonly code: "IDENTITY_NOT_CONFIGURED" }
  | { readonly code: "NOT_PUBLISHED"; readonly reason: PublishError };

export interface RevokeOutcome {
  readonly index: number;
  readonly agentDid?: string;
  readonly published: PublishOutcome;
}

const MAX_CREDENTIAL_FILE_BYTES = 65_536;

const invalid = (reason: string): { ok: false; error: RevokeError } => ({
  ok: false,
  error: { code: "INVALID_TARGET", reason },
});

async function targetFromCredential(
  path: string,
  listId: string,
  pinned: PinnedIdentity | undefined,
): Promise<{ ok: true; index: number; agentDid: string } | { ok: false; error: RevokeError }> {
  if (pinned === undefined) return { ok: false, error: { code: "IDENTITY_NOT_CONFIGURED" } };
  const key = multibaseToPublicKey(pinned.publicKeyMultibase);
  if (!key.ok) return invalid("the pinned identity key is not a valid public key");

  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    return invalid(
      `cannot read ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (text.length > MAX_CREDENTIAL_FILE_BYTES) return invalid("the credential file is too large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return invalid("the credential file is not JSON");
  }
  // `register --out` writes the bare credential; its JSON output wraps it.
  const candidate =
    typeof parsed === "object" && parsed !== null && "credential" in parsed
      ? (parsed as { credential: unknown }).credential
      : parsed;
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) {
    return invalid("not a credential");
  }
  const credential = candidate as Record<string, unknown>;
  if (credential.issuer !== pinned.did)
    return invalid("the credential was not issued by the pinned identity");

  const verified = await verifyCredential({
    credential: credential as unknown as SignedCredential,
    didDocument: pinnedDidDocument(pinned.did, key.value),
  });
  if (!verified.ok)
    return invalid(`the credential's signature does not verify (${verified.error.code})`);

  const subject = credential.credentialSubject as { id?: unknown } | undefined;
  const status = credential.credentialStatus as
    | {
        type?: unknown;
        statusPurpose?: unknown;
        statusListCredential?: unknown;
        statusListIndex?: unknown;
      }
    | undefined;
  if (typeof subject?.id !== "string" || subject.id === "")
    return invalid("the credential names no agent");
  if (
    status === undefined ||
    status.type !== "BitstringStatusListEntry" ||
    status.statusPurpose !== "revocation"
  ) {
    return invalid("the credential has no revocation status entry");
  }
  if (status.statusListCredential !== listId) {
    return invalid("the credential points at a different status list than this publisher's");
  }
  const index = parseStatusIndex(status.statusListIndex);
  if (index === undefined) return invalid("the credential's status index is not valid");
  return { ok: true, index, agentDid: subject.id };
}

/**
 * Revokes one agent from the operator's machine, with A's services off if need
 * be: validates who, records it in the journal (fsynced, the evidence and the
 * record of truth), then publishes under the lock. If the publish fails the
 * revocation is still recorded and the next publish carries it.
 */
export async function revokeFromPublisher(
  config: PublisherConfig,
  deps: PublisherDeps,
  input: {
    readonly target: RevokeTarget;
    readonly operator: string;
    readonly reason: string;
    readonly pinnedIdentity?: PinnedIdentity;
  },
): Promise<{ ok: true; value: RevokeOutcome } | { ok: false; error: RevokeError }> {
  if (input.operator.trim() === "" || input.reason.trim() === "") {
    return invalid("an operator name and a reason are required: they are what the journal records");
  }

  let index: number;
  let agentDid: string | undefined;
  if ("credentialPath" in input.target) {
    // The list address comes from the domain alone, not the key: with the key in
    // KMS, reading it here would let an outage stop the revocation being recorded.
    const resolved = await targetFromCredential(
      input.target.credentialPath,
      statusListCredentialUrl(config.domain),
      input.pinnedIdentity,
    );
    if (!resolved.ok) return resolved;
    ({ index, agentDid } = resolved);
  } else {
    if (input.target.index !== input.target.confirmIndex) {
      return invalid(
        "the index and its confirmation differ; revocation cannot be undone, so nothing was changed",
      );
    }
    const parsed = parseStatusIndex(input.target.index);
    if (parsed === undefined)
      return invalid("the index must be a decimal number within the status list's range");
    index = parsed;
  }

  // Refuse before writing anything if publishing could start from nothing: the
  // journal's existence is what says this publisher was initialised.
  const baseline = await hasBaseline(config, deps);
  if (!baseline.ok) return baseline;
  if (!baseline.value) return { ok: false, error: { code: "NO_BASELINE" } };

  await appendJournal(publisherPaths(config).journal, {
    index,
    at: deps.clock.now().toISOString(),
    operator: input.operator,
    reason: input.reason,
    ...(agentDid === undefined ? {} : { agentDid }),
  });

  const published = await publishOnce(config, deps);
  if (!published.ok)
    return { ok: false, error: { code: "NOT_PUBLISHED", reason: published.error } };
  return {
    ok: true,
    value: { index, ...(agentDid === undefined ? {} : { agentDid }), published: published.value },
  };
}

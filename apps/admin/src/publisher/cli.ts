import { Command } from "commander";
import {
  parsePublisherConfig,
  publisherKeyFromEnv,
  type ConfigError,
  type RawPublisherOptions,
} from "./config.js";
import { readJournal } from "./journal.js";
import {
  publishOnce,
  publisherIdentity,
  publisherPaths,
  runPublisher,
  type PublishError,
  type PublisherConfig,
  type PublisherDeps,
  type PublishResult,
} from "./publish.js";
import { revokeFromPublisher, type RevokeError } from "./revoke.js";

/** What the entry point supplies: everything that touches the outside world. */
export interface PublisherRuntime {
  readonly env: Record<string, string | undefined>;
  readonly clock: { now(): Date };
  readonly out: (line: string) => void;
  readonly fetchImpl?: typeof fetch;
  /** Revoked indexes from A's database, for `--use-database`. */
  readonly readDatabaseIndexes?: () => Promise<readonly number[]>;
  /** Aborts `run`; the entry point wires this to SIGINT/SIGTERM. */
  readonly signal?: AbortSignal;
  readonly sleep?: (ms: number) => Promise<void>;
}

const MAX_HOST_BODY_CHARS = 2_097_152;

function describe(error: PublishError | RevokeError | ConfigError): string {
  switch (error.code) {
    case "INVALID_CONFIG":
      return error.reason;
    case "NO_BASELINE":
      return "nothing to build on: no journal, and no list signed by this key survives. Run `publish-status init` once, or restore the journal.";
    case "ALREADY_INITIALISED":
      return `refusing to initialise: ${error.where}. Initialising again could replace earlier revocations.`;
    case "HOST_UNREACHABLE":
      return `refusing to initialise while the host cannot be read (${error.reason}): it might already be serving a list.`;
    case "LOCK_TIMEOUT":
      return "another publish is running and did not finish in time";
    case "LOCK_LOST":
      return "NOT PUBLISHED: another publish took over while this one was working. Nothing was written; try again.";
    case "INIT_NEEDS_HOST":
      return "refusing to initialise without checking for an existing list. Pass --host-url (a 404 means there is none), or --confirm-nothing-is-published if this publisher has never published.";
    case "KEY_MISMATCH":
      return `a list for this identity (${error.where}) is signed by a different key than CUSTOS_PUBLISHER_SIGNING_SEED. Nothing was changed. Compare with \`publish-status show\`; if the key was changed on purpose, remove the old files first.`;
    case "SIGNING_FAILED":
      return `signing failed: ${error.reason}`;
    case "WRITE_FAILED":
      return `NOT PUBLISHED: ${error.reason}`;
    case "JOURNAL_CORRUPT":
      return `the journal is damaged at line ${error.line} (${error.reason}); it is the record of truth, so nothing was published until a person has looked`;
    case "JOURNAL_UNREADABLE":
      return `the journal cannot be read: ${error.reason}`;
    case "INVALID_TARGET":
      return error.reason;
    case "IDENTITY_NOT_CONFIGURED":
      return "revoking by credential needs --identity-did and --identity-public-key (A's identity service, from its DID document)";
    case "NOT_PUBLISHED":
      return `recorded in the journal but NOT PUBLISHED (${describe(error.reason)}). The next publish will carry it.`;
  }
}

function hostFetcher(url: string, fetchImpl: typeof fetch): () => Promise<unknown | undefined> {
  return async () => {
    const response = await fetchImpl(url, { signal: AbortSignal.timeout(5_000) });
    if (response.status === 404) return undefined;
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const text = await response.text();
    if (text.length > MAX_HOST_BODY_CHARS) throw new Error("response body too large");
    return JSON.parse(text) as unknown;
  };
}

interface CommonOptions extends RawPublisherOptions {
  hostUrl?: string;
  useDatabase?: boolean;
}

function withCommon(command: Command): Command {
  return command
    .option("--domain <domain>", "domain the revocation DID is published under, e.g. a.example")
    .option("--dir <dir>", "where the journal, last signed state and lock are kept")
    .option("--out <file>", "the file a static server publishes (written atomically)")
    .option("--validity-seconds <n>", "how long each list is promised good for (no default)")
    .option("--max-clock-skew-seconds <n>", "how far a source list's time may be ahead (default 5)")
    .option("--host-url <url>", "also read the list from this host, to recover from it")
    .option("--use-database", "also read A's revoked agents from DATABASE_URL (optional)");
}

type Prepared =
  { ok: true; config: PublisherConfig; deps: PublisherDeps } | { ok: false; message: string };

function prepare(runtime: PublisherRuntime, options: CommonOptions, needsStamp: boolean): Prepared {
  const config = parsePublisherConfig(options, { needsStamp });
  if (!config.ok) return { ok: false, message: describe(config.error) };
  const key = publisherKeyFromEnv(runtime.env);
  if (!key.ok) return { ok: false, message: describe(key.error) };
  if (options.useDatabase === true && runtime.readDatabaseIndexes === undefined) {
    return { ok: false, message: "--use-database is not available here" };
  }
  return {
    ok: true,
    config: config.value,
    deps: {
      ...key.value,
      clock: runtime.clock,
      ...(options.hostUrl === undefined
        ? {}
        : { fetchHost: hostFetcher(options.hostUrl, runtime.fetchImpl ?? fetch) }),
      ...(options.useDatabase === true && runtime.readDatabaseIndexes !== undefined
        ? { readDatabaseIndexes: runtime.readDatabaseIndexes }
        : {}),
      ...(runtime.sleep === undefined ? {} : { sleep: runtime.sleep }),
    },
  };
}

function report(runtime: PublisherRuntime, result: PublishResult): void {
  if (!result.ok) {
    runtime.out(`error: ${describe(result.error)}`);
    return;
  }
  const { revokedCount, validFrom, validUntil, warnings } = result.value;
  runtime.out(
    `published: ${revokedCount} revoked, valid ${validFrom.toISOString()} to ${validUntil.toISOString()}`,
  );
  for (const warning of warnings) runtime.out(`warning: ${warning}`);
}

function fail(message: string): never {
  throw new Error(message);
}

/**
 * `custos-admin publish-status ...` (ADR 0014 step 3): the independent publisher
 * that signs and posts the status list from an operator's machine, with A's
 * services off if need be. File sink only.
 */
export function addPublishStatusCommands(program: Command, runtime: PublisherRuntime): void {
  const group = program
    .command("publish-status")
    .description("Sign and publish the revocation status list from this machine");

  withCommon(group.command("init"))
    .description(
      "Start a new publisher (once). Refused if a list signed by this key already exists.",
    )
    .option(
      "--confirm-nothing-is-published",
      "state that this publisher has never published (otherwise give --host-url, to check)",
    )
    .action(async (options: CommonOptions & { confirmNothingIsPublished?: boolean }) => {
      const prepared = prepare(runtime, options, false);
      if (!prepared.ok) fail(prepared.message);
      const result = await publishOnce(prepared.config, prepared.deps, {
        init: true,
        acknowledgeNoPublishedList: options.confirmNothingIsPublished === true,
      });
      report(runtime, result);
      if (!result.ok) fail("not initialised");
    });

  withCommon(group.command("once"))
    .description("Re-sign and publish once (a stamp)")
    .action(async (options: CommonOptions) => {
      const prepared = prepare(runtime, options, false);
      if (!prepared.ok) fail(prepared.message);
      const result = await publishOnce(prepared.config, prepared.deps);
      report(runtime, result);
      if (!result.ok) fail("not published");
    });

  withCommon(group.command("run"))
    .description("Re-sign every --stamp-seconds until stopped")
    .option(
      "--stamp-seconds <n>",
      "how often to re-sign; shorter than --validity-seconds (no default)",
    )
    .action(async (options: CommonOptions) => {
      const prepared = prepare(runtime, options, true);
      if (!prepared.ok) fail(prepared.message);
      const controller = new AbortController();
      const signal = runtime.signal ?? controller.signal;
      const last = await runPublisher(prepared.config, prepared.deps, {
        signal,
        onCycle: (result) => report(runtime, result),
      });
      if (last !== undefined && !last.ok) fail("stopped: needs a person");
    });

  withCommon(group.command("revoke"))
    .description("Revoke one agent, permanently, and publish it")
    .option("--credential <file>", "the agent's credential file (preferred)")
    .option("--index <n>", "the agent's status list index (fallback; also pass --confirm-index)")
    .option("--confirm-index <n>", "the same index again")
    .requiredOption("--operator <name>", "who is revoking, for the journal")
    .requiredOption("--reason <text>", "why, for the journal")
    .option("--identity-did <did>", "A's identity service DID, to check the credential against")
    .option("--identity-public-key <multibase>", "A's identity service key, from its DID document")
    .action(
      async (
        options: CommonOptions & {
          credential?: string;
          index?: string;
          confirmIndex?: string;
          operator: string;
          reason: string;
          identityDid?: string;
          identityPublicKey?: string;
        },
      ) => {
        const prepared = prepare(runtime, options, false);
        if (!prepared.ok) fail(prepared.message);
        const byCredential = options.credential !== undefined;
        const byIndex = options.index !== undefined || options.confirmIndex !== undefined;
        if (byCredential === byIndex)
          fail("give either --credential, or --index with --confirm-index");
        const result = await revokeFromPublisher(prepared.config, prepared.deps, {
          target: byCredential
            ? { credentialPath: options.credential! }
            : { index: options.index ?? "", confirmIndex: options.confirmIndex ?? "" },
          operator: options.operator,
          reason: options.reason,
          ...(options.identityDid !== undefined && options.identityPublicKey !== undefined
            ? {
                pinnedIdentity: {
                  did: options.identityDid,
                  publicKeyMultibase: options.identityPublicKey,
                },
              }
            : {}),
        });
        if (!result.ok) fail(describe(result.error));
        runtime.out(
          `revoked index ${result.value.index}${result.value.agentDid ? ` (${result.value.agentDid})` : ""}`,
        );
        report(runtime, { ok: true, value: result.value.published });
      },
    );

  group
    .command("show")
    .description(
      "Print the publisher's DID, list address and public key, to check against A's DID document",
    )
    .option("--domain <domain>", "domain the revocation DID is published under")
    .option("--dir <dir>", "the publisher's directory (to count journal entries)")
    .action(async (options: { domain?: string; dir?: string }) => {
      if (!options.domain) fail("--domain is required");
      const key = publisherKeyFromEnv(runtime.env);
      if (!key.ok) fail(describe(key.error));
      const config: PublisherConfig = {
        domain: options.domain,
        dir: options.dir ?? ".",
        out: "",
        validitySeconds: 1,
        stampSeconds: 1,
        maxClockSkewSeconds: 0,
      };
      const identity = await publisherIdentity(config, { ...key.value, clock: runtime.clock });
      runtime.out(`did:        ${identity.did}`);
      runtime.out(`list id:    ${identity.listId}`);
      runtime.out(`public key: ${identity.publicKeyMultibase}`);
      if (options.dir !== undefined) {
        const journal = await readJournal(publisherPaths(config).journal);
        runtime.out(
          journal.ok
            ? `journal:    ${journal.value.exists ? `${journal.value.entries.length} revocation(s)` : "not started"}`
            : `journal:    ${describe(journal.error)}`,
        );
      }
    });
}

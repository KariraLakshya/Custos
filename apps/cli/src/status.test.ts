import { createServer, type Server } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AUDIT_GENESIS_HASH,
  buildDidWebDocument,
  computeAuditEntryHash,
  computeAuditPayloadHash,
  generateKeyPair,
  issueAuditSeal,
  serializeAuditRecord,
  sign,
  type AuditRecord,
} from "@custos/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runCli } from "./cli.js";

const ID = "3f2b8c1e-1111-4111-8111-111111111111";
const DID = `did:web:localhost%3A4001:agents:${ID}`;
const ALICE = { kind: "operator", id: "k1", name: "alice@example.com", via: "sso" };

interface Reply {
  readonly status?: number;
  readonly body: unknown;
}

/** What each stub service answers; undefined takes the healthy default. */
interface Services {
  agents?: Reply;
  policies?: Reply;
  revocations?: Reply;
  records?: Reply;
  /** The agent's audit entries, sealed by the stub audit service. */
  actions?: AuditRecord[];
  /** Serve the ledger with one entry changed after sealing. */
  tamper?: boolean;
}

const listed = (overrides: Record<string, unknown> = {}) => ({
  agents: [
    {
      id: ID,
      did: DID,
      name: "billing-bot",
      registeredAt: "2026-11-20T10:00:00.000Z",
      registeredBy: ALICE,
      ...overrides,
    },
  ],
  nextCursor: null,
});

const grants = (tools: unknown[]) => ({
  grants: tools.map((tool) => ({
    agentDid: DID,
    tool,
    grantedBy: ALICE,
    createdAt: "2026-11-20T10:01:00.000Z",
  })),
  nextCursor: null,
});

const tombstone = (claims: Record<string, unknown>) =>
  `${Buffer.from(JSON.stringify(claims)).toString("base64url")}.c2ln`;

const revokedList = (reason?: string) => ({
  tombstones: [
    tombstone({
      agentDid: DID,
      statusListIndex: 3,
      revokedAt: "2026-11-20T10:05:00.000Z",
      ...(reason === undefined ? {} : { reason }),
    }),
  ],
  asOf: "2026-11-20T10:06:00.000Z",
});

function call(tool: string, action: string, decision: "allow" | "deny", at: string): AuditRecord {
  return {
    agentDid: DID,
    authorityChain: [DID],
    tool,
    action,
    dataCategories: [],
    policy: { rule: "agent-tool-allowlist", decision },
    recordedAt: at,
  };
}

const revokeEntry: AuditRecord = {
  agentDid: DID,
  principal: { kind: "operator", id: "k1", name: "alice@example.com" },
  authorityChain: [],
  action: "agents.revoke",
  dataCategories: [],
  policy: { rule: "control-plane-scope", decision: "allow" },
  recordedAt: "2026-11-20T10:05:00.000Z",
};

const defaultActions = [
  call("mock-database", "query", "allow", "2026-11-20T10:02:00.000Z"),
  call("stripe", "list-customers", "deny", "2026-11-20T10:03:00.000Z"),
];

let server: Server | undefined;
/** Re-seals the stub's ledger under a new key, at the same address. */
let rekey: () => Promise<void> = () => Promise.resolve();
let asked: { url: string; authorization: string | undefined }[] = [];

beforeEach(() => {
  vi.stubEnv("CUSTOS_OPERATOR_KEY", "test-operator-key");
  vi.stubEnv("CUSTOS_OPERATOR_KEY_FILE", join(tmpdir(), "custos-no-such-dir", "operator.key"));
  vi.stubEnv("CUSTOS_AUDIT_SEAL_STORE_URL", "");
});

afterEach(async () => {
  if (server) await new Promise((resolve) => server?.close(resolve));
  server = undefined;
  asked = [];
  process.exitCode = undefined;
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

/** A sealed audit ledger of `records`, as the audit service serves it. */
async function sealedLedger(port: number, records: AuditRecord[], tamper: boolean) {
  const { publicKey, secretKey } = generateKeyPair();
  const didDocument = buildDidWebDocument({ domain: `127.0.0.1:${port}`, publicKey });
  let prevHash = AUDIT_GENESIS_HASH;
  const entries = records.map((record, index) => {
    const seq = index + 1;
    const payload = serializeAuditRecord(record);
    const payloadHash = computeAuditPayloadHash(payload);
    prevHash = computeAuditEntryHash({ seq, prevHash, payloadHash });
    return { seq, payload, payloadHash };
  });
  const issued =
    entries.length === 0
      ? null
      : await issueAuditSeal({
          seal: {
            log: didDocument.id,
            seq: entries.length,
            headHash: prevHash,
            key: didDocument.verificationMethod[0].publicKeyMultibase,
            sealedAt: "2026-11-20T10:10:00.000Z",
          },
          signer: { sign: (data) => Promise.resolve(sign(data, secretKey)) },
        });
  if (issued !== null && !issued.ok) throw new Error("test setup: sealing failed");
  const served =
    tamper && entries[0] !== undefined
      ? [
          { ...entries[0], payload: entries[0].payload.replace("allow", "deny") },
          ...entries.slice(1),
        ]
      : entries;
  return { didDocument, body: { entries: served, seal: issued === null ? null : issued.value } };
}

/** One stub standing in for all four services, on a free port. */
async function serve(services: Services = {}): Promise<string> {
  let ledger: Awaited<ReturnType<typeof sealedLedger>> | undefined;
  server = createServer((req, res) => {
    const url = req.url ?? "";
    asked.push({ url, authorization: req.headers.authorization });
    const send = (reply: Reply) => {
      res.statusCode = reply.status ?? 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(reply.body));
    };
    const path = url.split("?")[0];
    if (path === "/agents") return send(services.agents ?? { body: listed() });
    if (path === "/policies") {
      return send(services.policies ?? { body: grants(["mock-database"]) });
    }
    if (path === "/revocations") {
      return send(services.revocations ?? { body: { tombstones: [], asOf: "x" } });
    }
    if (path === "/.well-known/did.json") return send({ body: ledger?.didDocument });
    if (path === "/records") return send(services.records ?? { body: ledger?.body });
    return send({ status: 404, body: { error: "NO_ROUTE" } });
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected a port");
  rekey = async () => {
    ledger = await sealedLedger(
      address.port,
      services.actions ?? defaultActions,
      services.tamper ?? false,
    );
  };
  await rekey();
  return `http://127.0.0.1:${address.port}`;
}

async function status(url: string, extra: string[] = [], agent = ID) {
  const sealFile = join(await mkdtemp(join(tmpdir(), "custos-status-")), "seal.json");
  const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  process.exitCode = undefined;
  await runCli([
    "node",
    "custos",
    "status",
    agent,
    "--identity-url",
    url,
    "--vault-url",
    url,
    "--revocation-url",
    url,
    "--audit-url",
    url,
    "--seal-file",
    sealFile,
    ...extra,
  ]);
  const result = {
    out: stdout.mock.calls.map(([chunk]) => String(chunk)).join(""),
    err: stderr.mock.calls.map(([chunk]) => String(chunk)).join(""),
    exitCode: process.exitCode,
  };
  stdout.mockRestore();
  stderr.mockRestore();
  return result;
}

describe("custos status (ADR 0022 §7)", () => {
  it("shows the name, who registered it, its grants, not cut off, and its verified recent actions", async () => {
    const url = await serve();
    const { out, err, exitCode } = await status(url);
    expect(out).toBe(
      [
        `billing-bot (id ${ID})`,
        "  Registered 2026-11-20T10:00:00.000Z by alice@example.com.",
        "  May use:",
        "    mock-database, granted 2026-11-20T10:01:00.000Z by alice@example.com",
        "  Cut off: no.",
        "  Recent actions, newest first (the audit log verified):",
        "  #2 2026-11-20T10:03:00.000Z  the agent list-customers on stripe: refused",
        "  #1 2026-11-20T10:02:00.000Z  the agent query on mock-database: allowed",
        `Next: custos audit-log ${ID}   (every recorded action, verified)`,
        "",
      ].join("\n"),
    );
    expect(err).toBe("");
    expect(exitCode).toBeUndefined();
  });

  it("sends the one operator key to every read, and reads by id", async () => {
    const url = await serve();
    await status(url);
    expect(asked.map((a) => a.url)).toEqual(
      expect.arrayContaining([
        `/agents?id=${ID}`,
        `/policies?agent=${encodeURIComponent(DID)}&limit=200`,
        "/revocations",
        `/records?agentId=${encodeURIComponent(DID)}`,
      ]),
    );
    const withKey = asked.filter((a) => a.url !== "/.well-known/did.json");
    expect(withKey.every((a) => a.authorization === "Bearer test-operator-key")).toBe(true);
  });

  it("reads by DID when given a DID", async () => {
    const url = await serve();
    expect((await status(url, [], DID)).exitCode).toBeUndefined();
    expect(asked[0]?.url).toBe(`/agents?did=${encodeURIComponent(DID)}`);
  });

  it("uses identity's DID for the other reads, not one worked out from the default issuer", async () => {
    const other = `did:web:127.0.0.1%3A9999:agents:${ID}`;
    const url = await serve({ agents: { body: listed({ did: other }) } });
    await status(url);
    expect(asked.map((a) => a.url)).toContain(
      `/policies?agent=${encodeURIComponent(other)}&limit=200`,
    );
  });

  it("shows an agent with no name as unnamed with a short DID, and says when the registrar was not recorded", async () => {
    const url = await serve({ agents: { body: listed({ name: null, registeredBy: null }) } });
    const { out } = await status(url);
    expect(out).toContain(`unnamed (did:web:localhost%3A4001:agents:3f2b8c1e…) (id ${ID})`);
    expect(out).toContain("who registered it was not recorded");
  });

  it("shows a revoked agent: when, by whom from the audit log, and why", async () => {
    const url = await serve({
      revocations: { body: revokedList("key leaked") },
      actions: [...defaultActions, revokeEntry],
    });
    const { out, exitCode } = await status(url);
    expect(out).toContain("  Cut off: yes, at 2026-11-20T10:05:00.000Z by alice@example.com.\n");
    expect(out).toContain("  Reason: key leaked\n");
    expect(out).toContain("alice@example.com agents.revoke: allowed");
    expect(out).toContain(`Next: custos audit-log ${ID}`);
    expect(exitCode).toBeUndefined();
  });

  it("does not name who cut it off when the audit log has no entry for it", async () => {
    const url = await serve({ revocations: { body: revokedList() } });
    const { out } = await status(url);
    expect(out).toContain("  Cut off: yes, at 2026-11-20T10:05:00.000Z.\n");
    expect(out).not.toContain("Reason:");
  });

  it("suggests a grant when the agent may use nothing", async () => {
    const url = await serve({ policies: { body: grants([]) }, actions: [] });
    const { out, exitCode } = await status(url);
    expect(out).toContain("  May use: no tools.\n");
    expect(out).toContain("  Recent actions: none recorded.\n");
    expect(out).toContain(`Next: custos grant <tool> --to ${ID}\n`);
    expect(exitCode).toBeUndefined();
  });

  it("refuses an unknown agent with a next step, reading nothing else", async () => {
    const url = await serve({ agents: { body: { agents: [], nextCursor: null } } });
    const { out, err, exitCode } = await status(url);
    expect(err).toBe(
      `error: no agent ${ID} is registered with the identity service at ${url}\nNext: check the id \`custos register\` printed, and --identity-url\n`,
    );
    expect(out).toBe("");
    expect(exitCode).toBe(1);
    expect(asked.map((a) => a.url)).toEqual([`/agents?id=${ID}`]);
  });

  it("refuses something that is not an id or DID before any request", async () => {
    const url = await serve();
    const { err, exitCode } = await status(url, [], "billing-bot");
    expect(err).toContain("error: that is not an agent id or DID");
    expect(exitCode).toBe(1);
    expect(asked).toEqual([]);
  });

  it("needs an operator key", async () => {
    vi.stubEnv("CUSTOS_OPERATOR_KEY", "");
    const url = await serve();
    const { err, exitCode } = await status(url);
    expect(err).toContain("error: you are not signed in as an operator\nNext: custos login");
    expect(exitCode).toBe(1);
    expect(asked).toEqual([]);
  });

  describe("one source failing while the others answer", () => {
    const unauthorized = { status: 401, body: { error: { code: "UNAUTHORIZED" } } };

    it("identity refused: names agents:read, and warns that empty answers below are unconfirmed", async () => {
      const url = await serve({ agents: unauthorized });
      const { out, err, exitCode } = await status(url);
      expect(out).toContain(`Agent ${ID}\n`);
      expect(out).toContain(
        "Could not check who this agent is (the identity service refused the read; the key needs agents:read).",
      );
      expect(out).toContain(`The lines below are for ${DID}, worked out from what you typed`);
      expect(out).toContain("mock-database");
      // An empty answer for a DID identity did not confirm is never stated as fact.
      expect(out).not.toContain("Cut off: no.");
      expect(out).toContain("  Cut off: no (not confirmed: identity could not be read).");
      expect(err).toContain(
        "Could not check who this agent is: the identity service refused the read. The key needs agents:read.\nRefused: ",
      );
      expect(err).toContain("Code: UNAUTHORIZED");
      expect(out).toContain(`Next: fix what is named above, then run again: custos status ${ID}`);
      expect(exitCode).toBe(1);
    });

    it("grants refused: never 'no tools'", async () => {
      const url = await serve({ policies: unauthorized });
      const { out, err, exitCode } = await status(url);
      expect(out).toContain(
        "  May use: could not check (the vault refused the read; the key needs policies:read). It may hold grants not shown here.",
      );
      expect(out).not.toContain("no tools");
      expect(err).toContain("The key needs policies:read.");
      expect(out).toContain("  Cut off: no.");
      expect(exitCode).toBe(1);
    });

    it("revocation refused: never 'not cut off'", async () => {
      const url = await serve({ revocations: unauthorized });
      const { out, err, exitCode } = await status(url);
      expect(out).toContain(
        "  Cut off: could not check (the revocation service refused the read; the key needs revocations:read). Do not assume either way.",
      );
      expect(out).not.toContain("Cut off: no");
      expect(err).toContain("The key needs revocations:read.");
      expect(exitCode).toBe(1);
    });

    it("revocation's own refusal in its older error shape: the catalogue words, no scope claim", async () => {
      const url = await serve({
        revocations: { status: 503, body: { error: "PUBLISHED_STATE_UNKNOWN" } },
      });
      const { out, err, exitCode } = await status(url);
      expect(out).toContain(
        "  Cut off: could not check (the revocation service refused the read).",
      );
      expect(err).toMatch(/^Problem: The revocation service has not yet confirmed/m);
      expect(err).toContain("Code: PUBLISHED_STATE_UNKNOWN");
      expect(err).not.toContain("The key needs");
      expect(exitCode).toBe(1);
    });

    it("a revocation list it cannot fully read is not 'not cut off'", async () => {
      const url = await serve({ revocations: { body: { tombstones: ["garbage"] } } });
      const { out, err } = await status(url);
      expect(out).toContain(
        "  Cut off: could not check (the revocation service's answer was not in the shape this command expects).",
      );
      expect(err).toContain(
        "Next: check that the revocation service and the custos command are the same version.",
      );
    });

    it("audit refused: names audit:read and shows no actions", async () => {
      const url = await serve({ records: unauthorized });
      const { out, err, exitCode } = await status(url);
      expect(out).toContain(
        "  Recent actions: could not check (the audit service refused the read; the key needs audit:read).",
      );
      expect(out).not.toContain("#1");
      expect(err).toContain("The key needs audit:read.");
      expect(exitCode).toBe(1);
    });

    it("a service that does not answer is named", async () => {
      const url = await serve();
      const { out, err, exitCode } = await status(url, ["--vault-url", "http://127.0.0.1:1"]);
      expect(out).toContain("  May use: could not check (the vault did not answer).");
      expect(err).toContain(
        "Could not check what it may use: the vault did not answer.\nProblem: ",
      );
      expect(err).toContain("Code: SERVICE_UNREACHABLE");
      expect(out).toContain("  Cut off: no.");
      expect(exitCode).toBe(1);
    });

    it("the audit service not answering is named", async () => {
      const url = await serve();
      const { out, exitCode } = await status(url, ["--audit-url", "http://127.0.0.1:1"]);
      expect(out).toContain(
        "  Recent actions: could not check (the audit service did not answer).",
      );
      expect(exitCode).toBe(1);
    });

    it("identity answering with a different agent is not trusted", async () => {
      const url = await serve({
        agents: { body: listed({ id: "00000000-0000-4000-8000-000000000000" }) },
      });
      const { out, exitCode } = await status(url);
      expect(out).toContain(
        "Could not check who this agent is (the identity service's answer was not in the shape this command expects).",
      );
      expect(out).not.toContain("billing-bot");
      expect(exitCode).toBe(1);
    });
  });

  it("shows a tampered audit log as an alarm, with none of its entries", async () => {
    const url = await serve({ tamper: true });
    const { out, err, exitCode } = await status(url);
    expect(out).toContain(
      "  Recent actions: ALARM. The audit log does not verify: it has been changed. Nothing from it is shown.",
    );
    expect(out).not.toContain("#1");
    expect(err).toMatch(/^Tampered: Entry #1 was changed after it was written\.$/m);
    expect(err).toContain("Code: PAYLOAD_MISMATCH");
    expect(exitCode).toBe(1);
  });

  it("after the audit seal key changes, says a person must check it, and how", async () => {
    const sealFile = join(await mkdtemp(join(tmpdir(), "custos-status-")), "seal.json");
    const url = await serve();
    expect((await status(url, ["--seal-file", sealFile])).exitCode).toBeUndefined();
    await rekey();
    const { out, err, exitCode } = await status(url, ["--seal-file", sealFile]);
    expect(out).toContain(
      "  Recent actions: not checked. The audit log is sealed with a key this machine has not trusted yet.",
    );
    expect(out).not.toContain("#1");
    expect(err).toMatch(/^Needs a person: /m);
    expect(err).toMatch(/If it matches, run again with: --accept-key z\S+/);
    expect(exitCode).toBe(1);
  });

  describe("strings off the wire", () => {
    const ESC = "\u001b[31m";

    it("prints none that are unsafe, and keeps them escaped in --json", async () => {
      const url = await serve({
        agents: {
          body: listed({
            name: `evil${ESC}`,
            registeredBy: { ...ALICE, name: `alice${ESC}` },
          }),
        },
        policies: { body: grants([`tool\nfake line`]) },
        revocations: { body: revokedList(`because\n${ESC}`) },
        actions: [
          {
            ...call("mock-database", `query${ESC}`, "allow", "2026-11-20T10:02:00.000Z"),
            tool: `db${ESC}`,
          },
        ],
      });
      const { out, err } = await status(url);
      expect(out + err).not.toContain("\u001b");
      expect(out).not.toContain("fake line");
      expect(out).toContain("its stored name cannot be shown safely");
      expect(out).toContain("Registered 2026-11-20T10:00:00.000Z by an operator.");
      expect(out).toContain("(a tool whose name cannot be shown safely; see --json)");
      expect(out).toContain("  Reason: given, but it cannot be shown safely; see --json.");
      expect(out).toContain("the agent (an action not shown) on (a tool): allowed");

      const json = await status(url, ["--json"]);
      expect(json.out).not.toContain("\u001b");
      const parsed = JSON.parse(json.out) as { identity: { name: string } };
      expect(parsed.identity.name).toBe(`evil${ESC}`);
    });

    it("escapes in --json what JSON.stringify leaves raw: DEL, C1 and bidi controls", async () => {
      // DEL, CSI (C1), right-to-left override, left-to-right isolate, line separator.
      const codes = [0x7f, 0x9b, 0x202e, 0x2066, 0x2028];
      const sneaky = codes.map((code) => `x${String.fromCharCode(code)}`).join("");
      const url = await serve({ revocations: { body: revokedList(sneaky) } });
      const { out } = await status(url, ["--json"]);
      for (const code of codes) {
        expect(out).not.toContain(String.fromCharCode(code));
        expect(out).toContain(`x\\u${code.toString(16).padStart(4, "0")}`);
      }
      expect((JSON.parse(out) as { revocation: { reason: string } }).revocation.reason).toBe(
        sneaky,
      );
    });

    it("says no tools and nothing recorded are unconfirmed when identity could not be read", async () => {
      const url = await serve({
        agents: { status: 401, body: { error: { code: "UNAUTHORIZED" } } },
        policies: { body: grants([]) },
        actions: [],
      });
      const { out } = await status(url);
      expect(out).toContain("  May use: no tools (not confirmed: identity could not be read).");
      expect(out).toContain(
        "  Recent actions: none recorded (not confirmed: identity could not be read).",
      );
    });

    it("does not print a timestamp that is not one", async () => {
      const url = await serve({
        agents: { body: listed({ registeredAt: "soon; run rm -rf" }) },
      });
      const { out } = await status(url);
      expect(out).toContain("  Registered (time not shown) by alice@example.com.");
    });
  });

  describe("--json", () => {
    it("gives every source's answer", async () => {
      const url = await serve({ revocations: { body: revokedList("key leaked") } });
      const { out, exitCode } = await status(url, ["--json"]);
      expect(exitCode).toBeUndefined();
      expect(JSON.parse(out)).toMatchObject({
        agent: { id: ID, did: DID },
        identity: { ok: true, name: "billing-bot", registeredBy: ALICE },
        grants: { ok: true, grants: [{ tool: "mock-database", grantedBy: ALICE }] },
        revocation: { ok: true, revoked: true, reason: "key leaked", statusListIndex: 3 },
        audit: {
          ok: true,
          verified: true,
          sealedThrough: 2,
          outsideSealsChecked: false,
          recent: [{ seq: 2 }, { seq: 1 }],
        },
      });
    });

    it("gives each failure with its service and scope, and exits 1", async () => {
      const url = await serve({
        agents: { status: 401, body: { error: { code: "UNAUTHORIZED" } } },
        revocations: { body: { tombstones: [] } },
        tamper: true,
      });
      const { out, exitCode } = await status(url, ["--json", "--vault-url", "http://127.0.0.1:1"]);
      expect(exitCode).toBe(1);
      expect(JSON.parse(out)).toMatchObject({
        identity: {
          ok: false,
          kind: "refused",
          code: "UNAUTHORIZED",
          service: "identity service",
          scope: "agents:read",
        },
        grants: { ok: false, kind: "unreachable", service: "vault", scope: "policies:read" },
        revocation: { ok: true, revoked: false },
        audit: {
          ok: false,
          verified: false,
          kind: "tampered",
          error: { code: "PAYLOAD_MISMATCH" },
        },
      });
    });

    it("gives a refused audit read with its scope", async () => {
      const url = await serve({
        records: { status: 401, body: { error: { code: "UNAUTHORIZED" } } },
      });
      const { out } = await status(url, ["--json"]);
      expect(JSON.parse(out)).toMatchObject({
        audit: { ok: false, kind: "refused", code: "UNAUTHORIZED", scope: "audit:read" },
      });
    });
  });
});

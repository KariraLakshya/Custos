import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { buildDidWebDocument, generateKeyPair, issueAuditRecord, sign } from "@custos/core";
import { pullAuditLog } from "./audit-log.js";

const AGENT_DID = "did:web:localhost%3A4001:agents:a1";

describe("pullAuditLog", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) await new Promise((resolve) => server?.close(resolve));
    server = undefined;
  });

  it("verifies every pulled record against the audit service's own resolved DID", async () => {
    const port = 4810;
    const domain = `127.0.0.1:${port}`;
    const { publicKey, secretKey } = generateKeyPair();
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const signer = { sign: (data: Uint8Array) => Promise.resolve(sign(data, secretKey)) };

    const issued = await issueAuditRecord({
      record: {
        agentDid: AGENT_DID,
        authorityChain: [AGENT_DID],
        tool: "mock-slack",
        action: "post-message",
        dataCategories: ["messaging-content"],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
        recordedAt: "2026-09-12T10:00:00.000Z",
      },
      signer,
    });
    if (!issued.ok) throw new Error("test setup: issuance failed");

    server = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/.well-known/did.json")) {
        res.end(JSON.stringify(didDocument));
        return;
      }
      res.end(JSON.stringify({ records: [issued.value] }));
    });
    await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));

    const entries = await pullAuditLog({ auditUrl: `http://127.0.0.1:${port}` });

    expect(entries).toHaveLength(1);
    expect(entries[0]!.verified).toBe(true);
    expect(entries[0]!.record?.agentDid).toBe(AGENT_DID);
  });

  it("passes the agentDid filter through as ?agentId=", async () => {
    const port = 4811;
    const domain = `127.0.0.1:${port}`;
    const { publicKey } = generateKeyPair();
    const didDocument = buildDidWebDocument({ domain, publicKey });

    let receivedUrl: string | undefined;
    server = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/.well-known/did.json")) {
        res.end(JSON.stringify(didDocument));
        return;
      }
      receivedUrl = req.url;
      res.end(JSON.stringify({ records: [] }));
    });
    await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));

    await pullAuditLog({ auditUrl: `http://127.0.0.1:${port}`, agentDid: AGENT_DID });

    expect(receivedUrl).toBe(`/records?agentId=${encodeURIComponent(AGENT_DID)}`);
  });

  it("reports a record that fails independent verification rather than dropping it", async () => {
    const port = 4812;
    const domain = `127.0.0.1:${port}`;
    const { publicKey, secretKey } = generateKeyPair();
    const didDocument = buildDidWebDocument({ domain, publicKey });
    const signer = { sign: (data: Uint8Array) => Promise.resolve(sign(data, secretKey)) };

    const issued = await issueAuditRecord({
      record: {
        agentDid: AGENT_DID,
        authorityChain: [AGENT_DID],
        tool: "stripe",
        action: "list-customers",
        dataCategories: [],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
        recordedAt: "2026-09-12T10:00:00.000Z",
      },
      signer,
    });
    if (!issued.ok) throw new Error("test setup: issuance failed");
    // Tamper with the record's claims after signing.
    const [, signature] = issued.value.split(".") as [string, string];
    const tamperedClaims = Buffer.from(
      JSON.stringify({
        agentDid: AGENT_DID,
        authorityChain: [AGENT_DID],
        tool: "stripe",
        action: "delete-everything",
        dataCategories: [],
        policy: { rule: "agent-tool-allowlist", decision: "allow" },
        recordedAt: "2026-09-12T10:00:00.000Z",
      }),
      "utf8",
    ).toString("base64url");
    const tampered = `${tamperedClaims}.${signature}`;

    server = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/.well-known/did.json")) {
        res.end(JSON.stringify(didDocument));
        return;
      }
      res.end(JSON.stringify({ records: [tampered] }));
    });
    await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));

    const entries = await pullAuditLog({ auditUrl: `http://127.0.0.1:${port}` });

    expect(entries).toEqual([{ verified: false, reason: "SIGNATURE_INVALID" }]);
  });

  it("throws when the audit service's DID document cannot be resolved", async () => {
    await expect(pullAuditLog({ auditUrl: "http://127.0.0.1:1" })).rejects.toThrow();
  });

  it("throws when the audit service rejects the /records request", async () => {
    const port = 4813;
    const domain = `127.0.0.1:${port}`;
    const { publicKey } = generateKeyPair();
    const didDocument = buildDidWebDocument({ domain, publicKey });

    server = createServer((req, res) => {
      if (req.url?.startsWith("/.well-known/did.json")) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(didDocument));
        return;
      }
      res.statusCode = 502;
      res.end();
    });
    await new Promise<void>((resolve) => server?.listen(port, "127.0.0.1", resolve));

    await expect(pullAuditLog({ auditUrl: `http://127.0.0.1:${port}` })).rejects.toThrow(
      /could not pull audit records.*502/,
    );
  });
});

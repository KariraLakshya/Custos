import { randomUUID } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { createDb } from "../db/client.js";
import { agentPolicies } from "../db/schema.js";
import { grantToolAccess, isToolAllowed, rootGrantOf } from "./policy.js";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos";
const db = createDb(databaseUrl);

afterAll(async () => {
  await db.$client.end();
});

const OPERATOR_KEY = {
  kind: "operator",
  id: "key-1",
  name: "ops-key",
  via: "custos-admin",
} as const;
const SSO_PERSON = {
  kind: "operator",
  id: "key-2",
  name: "alice@example.com",
  via: "sso",
} as const;
const SERVICE = { kind: "service", id: "spiffe://custos.local/service/x", name: "x" } as const;

const freshAgent = () => `did:web:localhost%3A4001:agents:${randomUUID()}`;

describe("grants and their granter (ADR 0020 §1)", () => {
  it("records who granted a tool, and an operator's grant is a delegation root", async () => {
    const agent = freshAgent();
    await grantToolAccess(db, agent, "mock-database", OPERATOR_KEY);
    expect(await isToolAllowed(db, agent, "mock-database")).toBe(true);
    expect(await rootGrantOf(db, agent, "mock-database")).toEqual(OPERATOR_KEY);
  });

  it("re-granting records the newer granter", async () => {
    const agent = freshAgent();
    await grantToolAccess(db, agent, "mock-database", OPERATOR_KEY);
    await grantToolAccess(db, agent, "mock-database", SSO_PERSON);
    expect(await rootGrantOf(db, agent, "mock-database")).toEqual(SSO_PERSON);
  });

  it("a grant made before granted_by existed still works for the agent but is no root", async () => {
    const agent = freshAgent();
    await db.insert(agentPolicies).values({ agentDid: agent, tool: "mock-database" });
    expect(await isToolAllowed(db, agent, "mock-database")).toBe(true);
    expect(await rootGrantOf(db, agent, "mock-database")).toBeNull();
  });

  it("a grant made by a service is no root", async () => {
    const agent = freshAgent();
    await grantToolAccess(db, agent, "mock-database", SERVICE);
    expect(await isToolAllowed(db, agent, "mock-database")).toBe(true);
    expect(await rootGrantOf(db, agent, "mock-database")).toBeNull();
  });

  it("no grant at all is no root", async () => {
    expect(await rootGrantOf(db, freshAgent(), "mock-database")).toBeNull();
  });

  it("a grant for another tool is no root for this one", async () => {
    const agent = freshAgent();
    await grantToolAccess(db, agent, "mock-slack", OPERATOR_KEY);
    expect(await rootGrantOf(db, agent, "mock-database")).toBeNull();
  });
});

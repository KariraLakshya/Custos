// Checks that sit behind the signature: the signing library's JSON-LD context
// already rejects some of these shapes at issuance, so they cannot be produced
// by signing. The verifier must still refuse them, because it may not rely on a
// library's context to protect a security decision. The signature step is
// replaced here so the checks after it can be reached directly.
import { describe, expect, it, vi } from "vitest";
import { ok } from "../result.js";
import type { Draft } from "./fixtures.js";

vi.mock("../vc/credential.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../vc/credential.js")>()),
  verifyCredential: vi.fn(({ credential }: { credential: unknown }) =>
    Promise.resolve(ok(credential)),
  ),
}));

const { verifyForeignAgent } = await import("./verify-agent.js");
const {
  issueAgent,
  makeOrganisation,
  memoryReplayGuard,
  NOW,
  proofFor,
  RECEIVER,
  REQUEST,
  STATUS_LIST_ID,
} = await import("./fixtures.js");

describe("verifyForeignAgent: behind the signature", () => {
  it("refuses a status entry of the wrong type", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    const credential = structuredClone(agent.credential) as unknown as Draft;
    credential.credentialStatus = {
      id: `${STATUS_LIST_ID}#7`,
      type: "SomethingElse",
      statusPurpose: "revocation",
      statusListIndex: "7",
      statusListCredential: STATUS_LIST_ID,
    };
    const result = await verifyForeignAgent({
      credential,
      proof: await proofFor(agent),
      anchors: [org.anchor],
      statusViewFor: () => undefined,
      audience: RECEIVER,
      request: REQUEST,
      replay: memoryReplayGuard(),
      now: NOW,
      maxProofSkewSeconds: 30,
      maxClockSkewSeconds: 5,
    });
    expect(result).toMatchObject({
      ok: false,
      error: { code: "STATUS_ENTRY_INVALID", reason: "not a revocation entry" },
    });
  });

  it("refuses a subject that is missing or not an object", async () => {
    const org = makeOrganisation();
    const agent = await issueAgent(org);
    for (const subject of [undefined, "x", null, []]) {
      const credential = structuredClone(agent.credential) as unknown as Draft;
      credential.credentialSubject = subject;
      const result = await verifyForeignAgent({
        credential,
        proof: await proofFor(agent),
        anchors: [org.anchor],
        statusViewFor: () => undefined,
        audience: RECEIVER,
        request: REQUEST,
        replay: memoryReplayGuard(),
        now: NOW,
        maxProofSkewSeconds: 30,
        maxClockSkewSeconds: 5,
      });
      expect(result).toMatchObject({
        ok: false,
        error: { code: "CREDENTIAL_SUBJECT_INVALID", reason: "no subject" },
      });
    }
  });
});

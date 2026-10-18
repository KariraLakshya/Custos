import { describe, expect, it } from "vitest";
import * as possession from "./possession.js";

describe("@custos/core/possession entry point", () => {
  it("exposes what an agent-side client needs to hold a key and prove possession", () => {
    expect(Object.keys(possession).sort()).toEqual([
      "FOREIGN_CALL_PROOF_TYPE",
      "REGISTRATION_PROOF_TYPE",
      "TOKEN_REQUEST_PROOF_TYPE",
      "buildForeignCallProof",
      "buildRegistrationRequest",
      "buildTokenRequestProof",
      "didWebFromDomain",
      "generateKeyPair",
      "issuePossessionProof",
      "publicKeyToMultibase",
      "sign",
    ]);
  });
});

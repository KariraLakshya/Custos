import { describe, expect, it } from "vitest";
import { createSigningKey } from "./signing-key.js";

const seed = (fill: number): string => Buffer.alloc(32, fill).toString("hex");

describe("createSigningKey (ADR 0012)", () => {
  it("derives the same public key from the same seed, independently each time", async () => {
    const first = createSigningKey({ REVOCATION_SIGNING_SEED: seed(1) });
    const second = createSigningKey({ REVOCATION_SIGNING_SEED: seed(1) });

    expect(await second.keyProvider.getPublicKey(second.keyId)).toEqual(
      await first.keyProvider.getPublicKey(first.keyId),
    );
  });

  it("derives a different public key from a different seed", async () => {
    const first = createSigningKey({ REVOCATION_SIGNING_SEED: seed(1) });
    const other = createSigningKey({ REVOCATION_SIGNING_SEED: seed(2) });

    expect(await other.keyProvider.getPublicKey(other.keyId)).not.toEqual(
      await first.keyProvider.getPublicKey(first.keyId),
    );
  });

  it("signs deterministically, so a restarted service re-serves identical signatures", async () => {
    const data = new TextEncoder().encode("tombstone");
    const first = createSigningKey({ REVOCATION_SIGNING_SEED: seed(1) });
    const second = createSigningKey({ REVOCATION_SIGNING_SEED: seed(1) });

    expect(await second.keyProvider.sign(second.keyId, data)).toEqual(
      await first.keyProvider.sign(first.keyId, data),
    );
  });
});

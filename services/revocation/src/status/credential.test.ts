import { createLocalKeyProvider, createStatusList, setRevoked } from "@custos/core";
import { describe, expect, it } from "vitest";
import { createStatusListMemo, signStatusList, type StatusListMemo } from "./credential.js";

// ADR 0016: the open status-list route reuses its last signature while the
// list is unchanged. Tested on fixed lists, with no database: the server tests
// share one with other files that revoke agents while they run.

const T0 = new Date("2026-09-07T10:00:00.000Z");
const ISSUER = "did:web:127.0.0.1%3A4503";

function countingSigner(options: { failing?: () => boolean } = {}) {
  const keys = createLocalKeyProvider({ importedKeys: { k: new Uint8Array(32).fill(7) } });
  const counter = { signs: 0 };
  return {
    counter,
    signer: {
      id: `${ISSUER}#key`,
      sign: async ({ data }: { readonly data: Uint8Array }) => {
        counter.signs += 1;
        if (options.failing?.()) throw new Error("ThrottlingException");
        return keys.sign("k", data);
      },
    },
  };
}

function listWith(...revoked: number[]): Uint8Array {
  let list = createStatusList(16);
  for (const index of revoked) {
    const updated = setRevoked(list, index, true);
    if (!updated.ok) throw new Error("fixture");
    list = updated.value;
  }
  return list;
}

function signer(
  signing: ReturnType<typeof countingSigner>,
  memo: StatusListMemo,
): (list: Uint8Array, now: Date) => ReturnType<typeof signStatusList> {
  return (list, now) =>
    signStatusList({
      list,
      issuerDid: ISSUER,
      signer: signing.signer,
      statusListCredentialUrl: "http://127.0.0.1:4503/status/revocation",
      now,
      memo,
    });
}

const at = (ms: number): Date => new Date(T0.getTime() + ms);

describe("signStatusList with a memo (ADR 0016)", () => {
  it("signs once for repeated requests within the window, serving the same list", async () => {
    const signing = countingSigner();
    const sign = signer(signing, createStatusListMemo(5_000));

    const first = await sign(listWith(3), T0);
    const later = [];
    for (let i = 0; i < 20; i += 1) later.push(await sign(listWith(3), at(4_999)));

    expect(signing.counter.signs).toBe(1);
    for (const result of later) expect(result).toEqual(first);
  });

  it("shares one signature between requests that arrive together", async () => {
    const signing = countingSigner();
    const sign = signer(signing, createStatusListMemo(5_000));

    const results = await Promise.all(Array.from({ length: 10 }, () => sign(listWith(3), T0)));

    expect(signing.counter.signs).toBe(1);
    for (const result of results) expect(result.ok).toBe(true);
  });

  it("signs again at once when the list changes, inside the window", async () => {
    const signing = countingSigner();
    const sign = signer(signing, createStatusListMemo(5_000));

    await sign(listWith(3), T0);
    const changed = await sign(listWith(3, 4), at(1_000));

    expect(signing.counter.signs).toBe(2);
    expect(changed.ok && changed.value.validFrom).toBe("2026-09-07T10:00:01.000Z");
  });

  it("signs a fresh list once the window has passed", async () => {
    const signing = countingSigner();
    const sign = signer(signing, createStatusListMemo(5_000));

    await sign(listWith(3), T0);
    const second = await sign(listWith(3), at(5_000));

    expect(signing.counter.signs).toBe(2);
    expect(second.ok && second.value.validFrom).toBe("2026-09-07T10:00:05.000Z");
  });

  it("signs a fresh list if the clock moves backwards", async () => {
    const signing = countingSigner();
    const sign = signer(signing, createStatusListMemo(5_000));

    await sign(listWith(3), T0);
    const second = await sign(listWith(3), at(-1_000));

    expect(signing.counter.signs).toBe(2);
    expect(second.ok && second.value.validFrom).toBe("2026-09-07T09:59:59.000Z");
  });

  it("does not reuse a failed signature: the next request signs again", async () => {
    let failing = true;
    const signing = countingSigner({ failing: () => failing });
    const sign = signer(signing, createStatusListMemo(5_000));

    expect(await sign(listWith(3), T0)).toMatchObject({
      ok: false,
      error: { code: "SIGNING_FAILED" },
    });
    failing = false;
    expect((await sign(listWith(3), T0)).ok).toBe(true);
    expect(signing.counter.signs).toBe(2);
  });

  it("signs every time without a memo", async () => {
    const signing = countingSigner();
    const keys = { list: listWith(3), now: T0 };

    for (let i = 0; i < 3; i += 1) {
      await signStatusList({
        ...keys,
        issuerDid: ISSUER,
        signer: signing.signer,
        statusListCredentialUrl: "http://127.0.0.1:4503/status/revocation",
      });
    }

    expect(signing.counter.signs).toBe(3);
  });
});

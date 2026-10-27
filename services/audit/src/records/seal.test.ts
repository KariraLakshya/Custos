import { describe, expect, it } from "vitest";
import { createCopyVerdicts } from "./seal.js";

// ADR 0017 part 2a: each seal's signature is checked once, however often the
// sealer ticks or the open status route is asked.
describe("createCopyVerdicts", () => {
  function counting(okSeals: ReadonlySet<string>) {
    const calls: string[] = [];
    const verdicts = createCopyVerdicts({
      log: "did:web:audit.example",
      key: "z6MkCurrent",
      verify: ({ seal, trustedKeys, log }) => {
        calls.push(`${seal}|${trustedKeys.join(",")}|${log}`);
        return okSeals.has(seal)
          ? { ok: true, value: {} as never }
          : { ok: false, error: { code: "SIGNATURE_INVALID" } };
      },
    });
    return { verdicts, calls };
  }

  it("verifies each seal once, under the current key and log, and remembers the answer", () => {
    const { verdicts, calls } = counting(new Set(["good"]));
    expect(verdicts.check(1, "good")).toEqual({ copyable: true, fresh: true });
    expect(verdicts.check(1, "good")).toEqual({ copyable: true, fresh: false });
    expect(verdicts.check(2, "bad")).toEqual({ copyable: false, fresh: true });
    expect(verdicts.check(2, "bad")).toEqual({ copyable: false, fresh: false });
    expect(calls).toEqual([
      "good|z6MkCurrent|did:web:audit.example",
      "bad|z6MkCurrent|did:web:audit.example",
    ]);
    expect([...verdicts.notCopyable()]).toEqual([2]);
  });

  it("checks again when the seal stored at a position is different", () => {
    const { verdicts, calls } = counting(new Set(["good"]));
    verdicts.check(1, "bad");
    expect(verdicts.check(1, "good")).toEqual({ copyable: true, fresh: true });
    expect(calls).toHaveLength(2);
  });
});

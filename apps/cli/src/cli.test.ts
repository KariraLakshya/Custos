import { describe, expect, it } from "vitest";
import { createCli } from "./cli.js";

describe("custos CLI", () => {
  it("reports its name and version", () => {
    const program = createCli();
    let output = "";
    program.exitOverride();
    program.configureOutput({
      writeOut: (str) => {
        output += str;
      },
    });

    expect(() => program.parse(["--version"], { from: "user" })).toThrow();
    expect(output.trim()).toBe("0.0.0");
    expect(program.name()).toBe("custos");
  });
});

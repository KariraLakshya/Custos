#!/usr/bin/env node
// Generates the mTLS certificate set by running gen-certs.sh inside a
// digest-pinned Alpine container with openssl (docs/adr/0009). No npm
// dependency and no openssl on the host: Docker is already required.
//
//   node infra/mtls/certs.mjs [outDir] [--with-negative-fixtures]
//
// outDir defaults to infra/mtls/certs (gitignored). Private keys are
// written owner-only and must never be committed.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const OPENSSL_IMAGE = JSON.parse(
  readFileSync(new URL("./images.json", import.meta.url), "utf8"),
).openssl;

const here = dirname(fileURLToPath(import.meta.url));

export function generateCerts(outDir, { negativeFixtures = false } = {}) {
  mkdirSync(outDir, { recursive: true });
  // The container runs as root (apk needs it). On Linux, it hands the
  // files back to the calling user, who also runs Envoy; see gen-certs.sh.
  const owner =
    typeof process.getuid === "function"
      ? ["-e", `OWNER=${process.getuid()}:${process.getgid()}`]
      : [];
  execFileSync(
    "docker",
    [
      "run",
      "--rm",
      ...owner,
      "-v",
      `${resolve(outDir)}:/out`,
      "-v",
      `${resolve(here, "gen-certs.sh")}:/gen-certs.sh:ro`,
      OPENSSL_IMAGE,
      "sh",
      "/gen-certs.sh",
      ...(negativeFixtures ? ["--with-negative-fixtures"] : []),
    ],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const outDir = resolve(args.find((arg) => !arg.startsWith("--")) ?? resolve(here, "certs"));
  generateCerts(outDir, { negativeFixtures: args.includes("--with-negative-fixtures") });
  process.stdout.write(`mTLS certificates written to ${outDir}\n`);
}

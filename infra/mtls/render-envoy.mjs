#!/usr/bin/env node
// Renders envoy.yaml.tmpl (docs/adr/0009). The dev stack and the proxy
// tests render the same template with different ports, so the tests prove
// the real config, not a copy of it.
//
//   node infra/mtls/render-envoy.mjs [outFile] [--set NAME=value ...]
//
// Without --set, the dev values below are used.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ENVOY_IMAGE = JSON.parse(
  readFileSync(new URL("./images.json", import.meta.url), "utf8"),
).envoy;

const here = dirname(fileURLToPath(import.meta.url));

export const DEV_ENVOY_VALUES = {
  REVOCATION_LISTEN_PORT: 5003,
  AUDIT_LISTEN_PORT: 5004,
  // Custos services run on the host in dev; Envoy runs in Docker.
  UPSTREAM_HOST: "host.docker.internal",
  REVOCATION_UPSTREAM_PORT: 4003,
  AUDIT_UPSTREAM_PORT: 4004,
};

export function renderEnvoyConfig(values) {
  const template = readFileSync(resolve(here, "envoy.yaml.tmpl"), "utf8");
  return template.replace(/\$\{([A-Z_]+)\}/g, (_match, name) => {
    if (!(name in values)) throw new Error(`render-envoy: no value for \${${name}}`);
    return String(values[name]);
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const values = { ...DEV_ENVOY_VALUES };
  let outFile = resolve(here, "envoy.yaml");
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--set") {
      const [name, value] = (args[++i] ?? "").split("=");
      if (!name || value === undefined) throw new Error("render-envoy: --set needs NAME=value");
      values[name] = value;
    } else {
      outFile = resolve(args[i]);
    }
  }
  writeFileSync(outFile, renderEnvoyConfig(values));
  process.stdout.write(`Envoy config written to ${outFile}\n`);
}

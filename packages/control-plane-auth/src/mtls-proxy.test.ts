import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import { request } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * The mTLS proxy, proven against the real thing (docs/adr/0009): the real
 * Envoy image running the real rendered config, real certificates from the
 * real generator, and real TLS from Node. Needs Docker, like the rest of
 * `pnpm test`.
 */

const repoRoot = resolve(__dirname, "../../..");
const mtlsDir = join(repoRoot, "infra/mtls");
const images = JSON.parse(readFileSync(join(mtlsDir, "images.json"), "utf8")) as {
  envoy: string;
};

const REVOCATION_LISTEN_PORT = 5103;
const AUDIT_LISTEN_PORT = 5104;
const XFCC = "x-forwarded-client-cert";
const SPIFFE = "spiffe://custos.local/service";

interface Upstream {
  readonly server: Server;
  readonly seen: IncomingHttpHeaders[];
}

/** Stands in for a Custos service behind Envoy: records what reached it. */
async function startUpstream(): Promise<Upstream> {
  const seen: IncomingHttpHeaders[] = [];
  const server = createServer((req, res) => {
    seen.push(req.headers);
    res.end("ok");
  });
  // All interfaces, IPv4 and IPv6 ("::" is dual-stack): Envoy reaches it from
  // inside Docker via host.docker.internal, which can resolve to either.
  await new Promise<void>((done) => server.listen(0, "::", done));
  return { server, seen };
}

const portOf = (upstream: Upstream): number => (upstream.server.address() as AddressInfo).port;

let dir: string;
let container: string;
let revocation: Upstream;
let audit: Upstream;

function pem(name: string): Buffer {
  return readFileSync(join(dir, name));
}

/** One HTTPS request through Envoy, presenting `client`'s certificate (or none). */
function callThroughEnvoy(
  port: number,
  client: string | null,
  headers: Record<string, string> = {},
): Promise<number> {
  return new Promise((resolveStatus, reject) => {
    const req = request(
      {
        host: "localhost",
        port,
        path: "/health",
        method: "GET",
        headers,
        ca: pem("ca.crt"),
        ...(client === null ? {} : { cert: pem(`${client}.crt`), key: pem(`${client}.key`) }),
        // A fresh connection per call, so one test's session can't carry over.
        agent: false,
      },
      (res) => {
        res.resume();
        res.on("end", () => resolveStatus(res.statusCode ?? 0));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "custos-mtls-"));
  execFileSync("node", [join(mtlsDir, "certs.mjs"), dir, "--with-negative-fixtures"]);

  revocation = await startUpstream();
  audit = await startUpstream();
  execFileSync("node", [
    join(mtlsDir, "render-envoy.mjs"),
    join(dir, "envoy.yaml"),
    "--set",
    `REVOCATION_LISTEN_PORT=${REVOCATION_LISTEN_PORT}`,
    "--set",
    `AUDIT_LISTEN_PORT=${AUDIT_LISTEN_PORT}`,
    "--set",
    `REVOCATION_UPSTREAM_PORT=${portOf(revocation)}`,
    "--set",
    `AUDIT_UPSTREAM_PORT=${portOf(audit)}`,
  ]);

  // As certs.mjs: on Linux the files belong to the calling user, so Envoy
  // runs as that user; on Docker Desktop the generator gave Envoy its key.
  const user =
    typeof process.getuid === "function"
      ? ["--user", `${process.getuid()}:${process.getgid?.()}`]
      : [];
  // A fixed name, removed first: if an earlier run was killed before its
  // afterAll, its container would otherwise keep the ports and fail every
  // later run.
  container = "custos-envoy-test";
  execFileSync("docker", ["rm", "-f", container], { stdio: "ignore" });
  execFileSync("docker", [
    "run",
    "-d",
    "--rm",
    "--name",
    container,
    ...user,
    "--add-host",
    "host.docker.internal:host-gateway",
    "-p",
    `${REVOCATION_LISTEN_PORT}:${REVOCATION_LISTEN_PORT}`,
    "-p",
    `${AUDIT_LISTEN_PORT}:${AUDIT_LISTEN_PORT}`,
    "-v",
    `${dir}:/etc/custos-mtls:ro`,
    "-v",
    `${join(dir, "envoy.yaml")}:/etc/envoy/envoy.yaml:ro`,
    images.envoy,
    "envoy",
    "-c",
    "/etc/envoy/envoy.yaml",
  ]);

  // Ready once a valid client gets all the way through to both upstreams.
  for (let attempt = 0; ; attempt += 1) {
    const statuses = await Promise.all([
      callThroughEnvoy(REVOCATION_LISTEN_PORT, "identity").catch(() => 0),
      callThroughEnvoy(AUDIT_LISTEN_PORT, "vault").catch(() => 0),
    ]);
    if (statuses.every((status) => status === 200)) break;
    if (attempt >= 60) throw new Error(`Envoy never became ready: ${statuses.join(", ")}`);
    await new Promise((done) => setTimeout(done, 500));
  }
  revocation.seen.length = 0;
  audit.seen.length = 0;
}, 180_000);

afterAll(async () => {
  if (container) execFileSync("docker", ["rm", "-f", container], { stdio: "ignore" });
  await Promise.all(
    [revocation, audit]
      .filter(Boolean)
      .map((upstream) => new Promise((done) => upstream.server.close(done))),
  );
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe("mTLS proxy (Envoy, ADR 0009)", () => {
  it("passes a valid service certificate through and tells the service who it is", async () => {
    expect(await callThroughEnvoy(REVOCATION_LISTEN_PORT, "identity")).toBe(200);
    expect(revocation.seen.at(-1)?.[XFCC]).toContain(`URI=${SPIFFE}/identity`);
  });

  it("replaces a forged identity header with the verified one", async () => {
    const forged = `URI=${SPIFFE}/vault`;
    expect(await callThroughEnvoy(REVOCATION_LISTEN_PORT, "identity", { [XFCC]: forged })).toBe(
      200,
    );
    const forwarded = String(revocation.seen.at(-1)?.[XFCC]);
    expect(forwarded).toContain(`URI=${SPIFFE}/identity`);
    expect(forwarded).not.toContain(`${SPIFFE}/vault`);
  });

  it("refuses an anonymous caller that brings its own identity header", async () => {
    await expect(
      callThroughEnvoy(REVOCATION_LISTEN_PORT, null, { [XFCC]: `URI=${SPIFFE}/identity` }),
    ).rejects.toMatchObject({ code: expect.stringMatching(/CERTIFICATE_REQUIRED/) });
  });

  it.each([
    ["no client certificate", null, /CERTIFICATE_REQUIRED/],
    ["an expired certificate", "expired", /CERTIFICATE_EXPIRED/],
    ["a certificate from another CA", "wrongca", /UNKNOWN_CA/],
    ["a self-signed certificate", "selfsigned", /UNKNOWN_CA/],
    ["a valid certificate with a name no listener allows", "wrongsan", /CERTIFICATE_UNKNOWN/],
  ] as const)(
    "refuses %s, for that reason, and nothing reaches the service",
    async (_label, client, reason) => {
      const before = revocation.seen.length;
      await expect(callThroughEnvoy(REVOCATION_LISTEN_PORT, client)).rejects.toMatchObject({
        code: expect.stringMatching(reason),
      });
      expect(revocation.seen.length).toBe(before);
    },
  );

  it("refuses a valid certificate for a service that may not call this one", async () => {
    // The vault's certificate is genuine, but only identity may reserve revocation slots.
    const before = revocation.seen.length;
    await expect(callThroughEnvoy(REVOCATION_LISTEN_PORT, "vault")).rejects.toMatchObject({
      code: expect.stringMatching(/CERTIFICATE_UNKNOWN/),
    });
    expect(revocation.seen.length).toBe(before);
  });

  it.each(["vault", "identity", "revocation"])(
    "lets %s write to the audit service, naming it",
    async (service) => {
      expect(await callThroughEnvoy(AUDIT_LISTEN_PORT, service)).toBe(200);
      expect(audit.seen.at(-1)?.[XFCC]).toContain(`URI=${SPIFFE}/${service}`);
    },
  );

  it.each([
    ["no client certificate", null, /CERTIFICATE_REQUIRED/],
    ["an expired certificate", "expired", /CERTIFICATE_EXPIRED/],
    ["a certificate from another CA", "wrongca", /UNKNOWN_CA/],
    ["a self-signed certificate", "selfsigned", /UNKNOWN_CA/],
    ["a valid certificate with a name no listener allows", "wrongsan", /CERTIFICATE_UNKNOWN/],
  ] as const)("audit listener refuses %s too, for that reason", async (_label, client, reason) => {
    const before = audit.seen.length;
    await expect(callThroughEnvoy(AUDIT_LISTEN_PORT, client)).rejects.toMatchObject({
      code: expect.stringMatching(reason),
    });
    expect(audit.seen.length).toBe(before);
  });
});

import { createPrivateKey, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  createServer as createHttpServer,
  type RequestListener,
  type Server as HttpServer,
} from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import type { TLSSocket } from "node:tls";
import { err, ok, type Result } from "@custos/contracts";
import { ENVOY_PROXY_URI } from "./mtls.js";

/** PEM contents of one mTLS identity: its certificate and key, and the CA it trusts. */
export interface MtlsIdentity {
  readonly cert: string;
  readonly key: string;
  readonly ca: string;
}

export interface MtlsFiles {
  readonly certFile: string;
  readonly keyFile: string;
  readonly caFile: string;
}

function sanUris(cert: X509Certificate): string[] {
  return (cert.subjectAltName ?? "")
    .split(", ")
    .filter((entry) => entry.startsWith("URI:"))
    .map((entry) => entry.slice("URI:".length));
}

/**
 * Loads an mTLS identity and checks it at boot, so a wrong file fails the
 * start-up rather than every later call: the key must belong to the
 * certificate, the certificate must be valid now, chain to the given CA,
 * and, when `expectedUri` is given, carry that SAN. Errors name files and
 * reasons, never key material.
 */
export function loadMtlsIdentity(
  files: MtlsFiles,
  options: { readonly now: Date; readonly expectedUri?: string },
): Result<MtlsIdentity, string> {
  let identity: MtlsIdentity;
  let cert: X509Certificate;
  let ca: X509Certificate;
  try {
    identity = {
      cert: readFileSync(files.certFile, "utf8"),
      key: readFileSync(files.keyFile, "utf8"),
      ca: readFileSync(files.caFile, "utf8"),
    };
    cert = new X509Certificate(identity.cert);
    ca = new X509Certificate(identity.ca);
    if (!cert.checkPrivateKey(createPrivateKey(identity.key))) {
      return err(`${files.keyFile} is not the key for ${files.certFile}`);
    }
  } catch (error) {
    return err(`cannot load mTLS files: ${error instanceof Error ? error.message : String(error)}`);
  }
  const now = options.now.getTime();
  if (now < Date.parse(cert.validFrom) || now >= Date.parse(cert.validTo)) {
    return err(`${files.certFile} is not valid now (valid ${cert.validFrom} to ${cert.validTo})`);
  }
  if (!cert.verify(ca.publicKey)) return err(`${files.certFile} is not signed by ${files.caFile}`);
  if (options.expectedUri !== undefined && !sanUris(cert).includes(options.expectedUri)) {
    return err(`${files.certFile} is not for ${options.expectedUri}`);
  }
  return ok(identity);
}

export interface EnvoyOnlyTlsListener {
  /** Pass to `Fastify({ serverFactory })`: one app behind both listeners. */
  readonly serverFactory: (handler: RequestListener) => HttpServer;
  /** Resolves with the port bound (useful with port 0). */
  listen(port: number, host: string): Promise<number>;
  close(): Promise<void>;
}

/**
 * A second, TLS-only listener for a service behind Envoy (ADR 0009 part B).
 * It serves the same Fastify app as the plain listener, but accepts a
 * connection only from a client certificate signed by the Custos CA whose
 * SAN is Envoy's. Any other client, including another genuine Custos
 * service, is disconnected during the handshake. Only on this listener can
 * `requireScope` see Envoy as the verified TLS peer, and so trust the
 * identity header Envoy sets.
 */
export function createEnvoyOnlyTlsListener(identity: MtlsIdentity): EnvoyOnlyTlsListener {
  let tlsServer: HttpsServer | undefined;
  return {
    serverFactory(handler) {
      tlsServer = createHttpsServer(
        {
          cert: identity.cert,
          key: identity.key,
          ca: identity.ca,
          requestCert: true,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
        },
        handler,
      );
      tlsServer.on("secureConnection", (socket: TLSSocket) => {
        const san = socket.getPeerCertificate().subjectaltname ?? "";
        if (!san.split(", ").includes(`URI:${ENVOY_PROXY_URI}`)) socket.destroy();
      });
      return createHttpServer(handler);
    },
    listen(port, host) {
      const server = tlsServer;
      if (!server) throw new Error("createEnvoyOnlyTlsListener: serverFactory was never used");
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          const address = server.address();
          resolve(typeof address === "object" && address !== null ? address.port : port);
        });
      });
    },
    close() {
      const server = tlsServer;
      if (!server?.listening) return Promise.resolve();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

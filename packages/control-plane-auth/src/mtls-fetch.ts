import { request } from "node:https";
import type { MtlsIdentity } from "./mtls-server.js";

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

/**
 * A `fetch` for one Custos service calling another through Envoy with its
 * own client certificate (ADR 0009). Node's global `fetch` can't present a
 * client certificate without the `undici` package, so this uses the
 * built-in `node:https` instead: no new dependency. It covers what Custos's
 * callers use (method, headers, string body, abort signal) and refuses
 * anything but `https:`, so a misconfigured URL can't silently go
 * unauthenticated.
 */
export function createMtlsFetch(identity: MtlsIdentity): typeof fetch {
  const mtlsFetch = (input: string | URL | Request, init: RequestInit = {}): Promise<Response> =>
    new Promise((resolve, reject) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.protocol !== "https:") {
        reject(new Error(`mTLS fetch needs an https URL, got ${url.protocol}`));
        return;
      }
      if (init.body !== undefined && init.body !== null && typeof init.body !== "string") {
        reject(new Error("mTLS fetch supports string bodies only"));
        return;
      }
      const req = request(
        url,
        {
          method: init.method ?? "GET",
          headers: Object.fromEntries(new Headers(init.headers).entries()),
          cert: identity.cert,
          key: identity.key,
          ca: identity.ca,
          ...(init.signal ? { signal: init.signal } : {}),
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("error", reject);
          res.on("end", () => {
            const status = res.statusCode ?? 502;
            const headers = new Headers();
            for (const [name, value] of Object.entries(res.headers)) {
              for (const item of Array.isArray(value) ? value : [value]) {
                if (item !== undefined) headers.append(name, item);
              }
            }
            const body = NULL_BODY_STATUSES.has(status) ? null : Buffer.concat(chunks);
            resolve(new Response(body, { status, headers }));
          });
        },
      );
      req.on("error", reject);
      if (typeof init.body === "string") req.write(init.body);
      req.end();
    });
  // The callers type their injected fetch as `typeof fetch`; this implements
  // the subset they use, and rejects anything else explicitly.
  return mtlsFetch as typeof fetch;
}

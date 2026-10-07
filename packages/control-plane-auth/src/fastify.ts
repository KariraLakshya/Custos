import { ErrorCode } from "@custos/contracts";
import { TLSSocket } from "node:tls";
import type { FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from "fastify";
import type { ControlPlaneAuthenticator, Principal } from "./authenticator.js";
import type { Lockout } from "./lockout.js";
import type { Scope } from "./scopes.js";

const principals = new WeakMap<FastifyRequest, Principal>();

/** The principal `requireScope` authenticated for this request. */
export function principalOf(request: FastifyRequest): Principal {
  const principal = principals.get(request);
  // Programmer error: the route was registered without `requireScope`.
  if (!principal) throw new Error("principalOf: route has no requireScope preHandler");
  return principal;
}

/**
 * SAN URIs of the client certificate this server verified on the request's
 * own TLS connection. Empty unless the socket is TLS and the peer's
 * certificate passed verification; nothing here comes from the request.
 */
export function verifiedPeerUris(request: FastifyRequest): readonly string[] {
  const socket = request.raw.socket;
  if (!(socket instanceof TLSSocket) || !socket.authorized) return [];
  const san = socket.getPeerCertificate().subjectaltname ?? "";
  return san
    .split(", ")
    .filter((entry) => entry.startsWith("URI:"))
    .map((entry) => entry.slice("URI:".length));
}

function refuse(reply: FastifyReply): FastifyReply {
  return reply.code(401).send({ error: { code: ErrorCode.UNAUTHORIZED } });
}

/**
 * Route preHandler: authenticates the caller and requires `scope`, deny by
 * default (ADR 0008 §3). A missing, malformed, unknown, wrong, revoked or
 * expired key, a missing scope, and a locked-out source all get the same
 * 401 — the reason is logged by key id, never the response or the secret.
 * Only authentication failures count towards the lockout; a valid key
 * lacking a scope is not a guess.
 *
 * `onScopeDenied` fires only for that second case — an authenticated
 * principal refused for a missing scope — so the service can audit it (ADR
 * 0008 §7). Failed authentication is logged, never audited: there is no
 * principal to attribute it to, and letting unauthenticated traffic write
 * to the evidence log would let anyone flood it.
 */
export function requireScope(options: {
  readonly authenticator: ControlPlaneAuthenticator;
  readonly lockout: Lockout;
  readonly scope: Scope;
  readonly onScopeDenied?: (principal: Principal) => void;
}): preHandlerAsyncHookHandler {
  return async (request, reply) => {
    const source = request.ip;
    if (options.lockout.isLocked(source)) {
      request.log.warn({ source }, "control-plane request refused: source locked out");
      return refuse(reply);
    }

    const result = await options.authenticator.authenticate({
      headers: request.headers,
      tlsPeerUris: verifiedPeerUris(request),
    });
    if (!result.ok) {
      options.lockout.recordFailure(source);
      request.log.warn(
        { source, reason: result.error.reason, keyId: result.error.keyId },
        "control-plane authentication failed",
      );
      return refuse(reply);
    }

    const principal = result.value;
    if (!principal.scopes.has(options.scope)) {
      request.log.warn(
        { keyId: principal.id, scope: options.scope },
        "control-plane request refused: missing scope",
      );
      options.onScopeDenied?.(principal);
      return refuse(reply);
    }
    principals.set(request, principal);
  };
}

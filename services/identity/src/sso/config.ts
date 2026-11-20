import { isScope, READ_SCOPES, scopeAllowedFor, type Scope } from "@custos/control-plane-auth";
import { err, ok, type Result } from "@custos/core";

/**
 * Company groups → operator scopes (ADR 0010 §4), from `SSO_GROUP_SCOPES`.
 * Strict: unknown scopes and service-only scopes are refused at boot, so a
 * typo can't silently grant nothing, and SSO can never mint a service's
 * powers.
 */
export function parseGroupScopes(
  json: string,
): Result<ReadonlyMap<string, readonly Scope[]>, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return err("SSO_GROUP_SCOPES is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return err("SSO_GROUP_SCOPES must be an object of group name to scope list");
  }
  const map = new Map<string, readonly Scope[]>();
  for (const [group, scopes] of Object.entries(parsed)) {
    if (!Array.isArray(scopes) || !scopes.every((scope) => typeof scope === "string")) {
      return err(`SSO_GROUP_SCOPES.${group} must be a list of scopes`);
    }
    for (const scope of scopes) {
      if (!isScope(scope)) return err(`SSO_GROUP_SCOPES.${group}: unknown scope ${scope}`);
      if (!scopeAllowedFor("operator", scope)) {
        return err(`SSO_GROUP_SCOPES.${group}: ${scope} is service-only`);
      }
    }
    map.set(group, scopes as Scope[]);
  }
  if (map.size === 0) return err("SSO_GROUP_SCOPES maps no groups");
  return ok(map);
}

/** The union of scopes for the groups a person is in that the mapping knows. */
export function scopesForGroups(
  groups: unknown,
  mapping: ReadonlyMap<string, readonly Scope[]>,
): { readonly matched: boolean; readonly scopes: readonly Scope[] } {
  if (!Array.isArray(groups)) return { matched: false, scopes: [] };
  const scopes = new Set<Scope>();
  let matched = false;
  for (const group of groups) {
    const mapped = typeof group === "string" ? mapping.get(group) : undefined;
    if (mapped === undefined) continue;
    matched = true;
    for (const scope of mapped) scopes.add(scope);
  }
  return { matched, scopes: [...scopes].sort() };
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * The addresses a dashboard sign-in may return to (ADR 0022 §4), from
 * `SSO_RETURN_URLS`: a JSON list of absolute URLs, compared later by exact
 * string equality only. Each must already be in its canonical form (what
 * `new URL()` prints), so the string compared is the string redirected to.
 * No query, fragment or user info; `https`, or `http` for this computer only,
 * since the one-time code travels in the address.
 */
export function parseReturnUrls(json: string): Result<ReadonlySet<string>, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return err("SSO_RETURN_URLS is not valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    return err("SSO_RETURN_URLS must be a non-empty list of addresses");
  }
  const urls = new Set<string>();
  for (const entry of parsed) {
    if (typeof entry !== "string") return err("SSO_RETURN_URLS must list strings");
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      return err(`SSO_RETURN_URLS: ${JSON.stringify(entry)} is not an absolute URL`);
    }
    if (url.href !== entry) {
      return err(`SSO_RETURN_URLS: write ${JSON.stringify(entry)} as ${JSON.stringify(url.href)}`);
    }
    if (entry.includes("?") || entry.includes("#") || url.username !== "" || url.password !== "") {
      return err(`SSO_RETURN_URLS: ${entry} must have no query, fragment or user info`);
    }
    const local = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
    if (url.protocol !== "https:" && !local) {
      return err(`SSO_RETURN_URLS: ${entry} must be https (http only for localhost)`);
    }
    urls.add(entry);
  }
  return ok(urls);
}

/** A dashboard sign-in's scopes: only the group's read scopes (ADR 0022 §4). */
export function readOnly(scopes: readonly Scope[]): readonly Scope[] {
  return scopes.filter((scope) => (READ_SCOPES as readonly Scope[]).includes(scope));
}

import { isScope, scopeAllowedFor, type Scope } from "@custos/control-plane-auth";
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

export interface GrantResult {
  readonly agentId: string;
  readonly tool: string;
}

/**
 * Grants an agent access to one tool (build plan Phase 4: "simple allowlists
 * per agent × tool"). Without a grant the vault refuses to issue a token for
 * that tool at all — deny by default.
 */
export async function grantToolAccess(params: {
  readonly vaultUrl: string;
  readonly agentDid: string;
  readonly tool: string;
}): Promise<GrantResult> {
  const { vaultUrl, agentDid, tool } = params;
  const response = await fetch(new URL("/policies", vaultUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ agentId: agentDid, tool }),
  });
  if (!response.ok) {
    throw new Error(
      `grant failed: vault returned ${response.status} — ${JSON.stringify(await response.json())}`,
    );
  }
  return (await response.json()) as GrantResult;
}

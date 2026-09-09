export interface DeprovisionResult {
  readonly agentId: string;
  readonly agentDid: string;
  readonly statusListIndex: number;
  readonly revokedAt: string;
  readonly alreadyRevoked: boolean;
  readonly broadcast: { readonly delivered: number; readonly failed: readonly string[] };
}

/**
 * The Phase 3 headline: one call to the revocation service's control plane,
 * which flips the agent's status list bit and pushes a signed tombstone to
 * every subscribed vault. Cutting the agent off at every tool is the vault's
 * and connectors' job from there (CLAUDE.md section 3, "push, don't pull") —
 * this command only has to trigger it.
 */
export async function deprovisionAgent(params: {
  readonly revocationUrl: string;
  readonly agentId: string;
  readonly reason?: string;
}): Promise<DeprovisionResult> {
  const { revocationUrl, agentId, reason } = params;

  const response = await fetch(new URL("/revocations", revocationUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(reason === undefined ? { agentId } : { agentId, reason }),
  });
  if (!response.ok) {
    throw new Error(
      `deprovision failed: revocation service returned ${response.status} — ${JSON.stringify(await response.json())}`,
    );
  }
  return (await response.json()) as DeprovisionResult;
}

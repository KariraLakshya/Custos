import { readFile } from "node:fs/promises";
import type { SignedCredential } from "@custos/core";

export interface UseToolResult {
  readonly result: unknown;
}

async function postJson(url: URL, body: unknown): Promise<{ status: number; body: unknown }> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

/** Reads a credential file written by `custos register --out`. */
export async function loadAgentCredential(path: string): Promise<SignedCredential> {
  const raw = await readFile(path, "utf8");
  return JSON.parse(raw) as SignedCredential;
}

/**
 * The Phase 2 lifecycle in one call: request a scoped, 60s-default token for
 * `tool`/`action` from the vault, then immediately spend it. Agents never
 * receive the real tool credential — the vault holds it and calls the tool
 * on the agent's behalf (CLAUDE.md section 4).
 */
export async function useTool(params: {
  readonly vaultUrl: string;
  readonly credential: SignedCredential;
  readonly tool: string;
  readonly action: string;
  readonly input?: unknown;
}): Promise<UseToolResult> {
  const { vaultUrl, credential, tool, action, input } = params;

  const tokenResponse = await postJson(new URL("/tokens", vaultUrl), { tool, action, credential });
  if (tokenResponse.status !== 200) {
    throw new Error(
      `token request failed: vault returned ${tokenResponse.status} — ${JSON.stringify(tokenResponse.body)}`,
    );
  }
  const { token } = tokenResponse.body as { token: string };

  const callResponse = await postJson(new URL("/call", vaultUrl), { token, action, input });
  if (callResponse.status !== 200) {
    throw new Error(
      `call failed: vault returned ${callResponse.status} — ${JSON.stringify(callResponse.body)}`,
    );
  }
  return callResponse.body as UseToolResult;
}

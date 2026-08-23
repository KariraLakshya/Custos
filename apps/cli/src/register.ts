export interface RegisterResult {
  readonly id: string;
  readonly did: string;
  readonly didDocument: unknown;
  readonly credential: unknown;
}

export async function registerAgent(identityUrl: string): Promise<RegisterResult> {
  const response = await fetch(new URL("/agents", identityUrl), { method: "POST" });
  if (!response.ok) {
    throw new Error(`registration failed: identity service returned ${response.status}`);
  }
  return (await response.json()) as RegisterResult;
}

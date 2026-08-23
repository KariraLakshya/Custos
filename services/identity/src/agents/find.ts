import { eq } from "drizzle-orm";
import type { DidWebDocument } from "@custos/core";
import { agents } from "../db/schema.js";
import type { IdentityDb } from "../db/client.js";

export async function findAgentDidDocumentById(
  db: IdentityDb,
  id: string,
): Promise<DidWebDocument | null> {
  const [row] = await db
    .select({ didDocument: agents.didDocument })
    .from(agents)
    .where(eq(agents.id, id))
    .limit(1);
  return (row?.didDocument as DidWebDocument | undefined) ?? null;
}

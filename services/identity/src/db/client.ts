import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "./schema.js";

export function createDb(databaseUrl: string) {
  return drizzle(databaseUrl, { schema });
}

export type IdentityDb = ReturnType<typeof createDb>;

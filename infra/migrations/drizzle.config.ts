import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "postgresql",
  schema: ["./services/identity/src/db/schema.ts", "./services/vault/src/db/schema.ts"],
  out: "./infra/migrations",
  dbCredentials: {
    url: process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos",
  },
});

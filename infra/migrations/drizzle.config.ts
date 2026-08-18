import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "postgresql",
  schema: "./infra/migrations/schema.ts",
  out: "./infra/migrations",
  dbCredentials: {
    url: process.env.DATABASE_URL ?? "postgres://custos:custos@localhost:5433/custos",
  },
});

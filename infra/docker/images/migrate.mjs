// `custos-migrate` in the custos-tools image: applies infra/migrations to
// DATABASE_URL. This is the migrator `drizzle-kit migrate` itself runs (same
// journal, same drizzle.__drizzle_migrations table), so a database migrated
// by `pnpm migrate` on the host and by this image stay interchangeable. It
// avoids shipping drizzle-kit, a root devDependency, in the image (ADR 0019).
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";

const url = process.env.DATABASE_URL;
if (!url) {
  process.stderr.write("error: DATABASE_URL is required\n");
  process.exit(1);
}

const db = drizzle(url);
try {
  await migrate(db, { migrationsFolder: "/opt/custos/migrations" });
  process.stdout.write("migrations applied\n");
} finally {
  await db.$client.end();
}

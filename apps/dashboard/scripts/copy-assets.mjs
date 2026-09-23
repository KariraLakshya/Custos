// Copies the one static asset tsc doesn't know about next to the compiled
// server so `dist/server.js`'s relative `join(__dirname, "index.html")`
// resolves in production the same way it resolves against `src/` in tests.
// Plain Node `fs`, not a shell `cp` — this repo's build steps run on
// Windows, where `cp` isn't guaranteed to exist.
import { copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
copyFileSync(join(root, "src", "index.html"), join(root, "dist", "index.html"));

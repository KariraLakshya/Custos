import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const indexHtmlPath = join(here, "index.html");

/**
 * Phase 5's "minimal dashboard that makes the revocation moment visual"
 * (`docs/build-plan.md`). One static page, no framework, no build step
 * beyond copying it next to the compiled server (`scripts/copy-assets.mjs`)
 * — it polls the real running audit and revocation services directly from
 * the browser (see `index.html`) and asks nothing more of this process than
 * "serve that one file."
 *
 * This is a monitoring view, not a verification tool: it displays what the
 * services report without re-checking any signature client-side — reading
 * decisions off a dashboard is not a security boundary. `custos audit-log`
 * remains the command that independently verifies every record.
 */
export function buildServer(): Server {
  return createServer((_request, response) => {
    readFile(indexHtmlPath)
      .then((html) => {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(html);
      })
      .catch(() => {
        response.writeHead(500, { "content-type": "text/plain" });
        response.end("dashboard: could not read index.html");
      });
  });
}

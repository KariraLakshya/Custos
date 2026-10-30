#
# Custos container images (ADR 0019). One build, six targets:
#   identity, vault, revocation, audit, dashboard  - one service each
#   tools                                           - migrations, custos-admin, custos CLI
#
# Build from the repository root (the build context), e.g.
#   docker build -f infra/docker/images/Dockerfile --target identity -t custos-identity:local .
# `pnpm images:build` builds all six.
#
# No secret is ever an input to this build: seeds, keys and passwords reach a
# container only at runtime (infra/docker/images.env, written by env.sh).

# Node 22 LTS, Debian bookworm slim, pinned by digest, named once here so
# Dependabot (docker ecosystem) can read and bump it. Bump it deliberately.
FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da AS node-base

# ---------------------------------------------------------------------------
# builder: install from the lockfile, build every package, then lay out one
# self-contained directory per image with `pnpm deploy --prod`.
FROM node-base AS builder
ENV HUSKY=0 \
    TURBO_TELEMETRY_DISABLED=1 \
    CI=1
RUN npm install --global pnpm@9.15.0
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm build
RUN set -eu; \
    for pkg in identity vault revocation audit dashboard admin cli; do \
      pnpm --filter "@custos/$pkg" deploy --prod "/out/$pkg"; \
    done
# Ship compiled output only: drop sources, tests and build config from each
# deployed package and from the workspace packages injected into it.
RUN set -eu; \
    find /out -type d -name node_modules -prune -o -type f \( -name '*.ts' -o -name '*.tsx' -o -name 'tsconfig*.json' -o -name 'vitest*.config.*' -o -name 'eslint.config.*' \) -print | xargs -r rm -f; \
    for dir in /out/* /out/*/node_modules/.pnpm/node_modules/@custos/* /out/*/node_modules/@custos/*; do \
      [ -d "$dir" ] || continue; \
      real="$(readlink -f "$dir")"; \
      rm -rf "$real/src" "$real/scripts" "$real/test" "$real/tests" "$real/coverage" \
        "$real"/tsconfig*.json "$real"/vitest*.config.* "$real"/eslint.config.*; \
    done; \
    find /out -name '*.test.js' -o -name '*.test.d.ts' -o -name '*.test.js.map' | xargs -r rm -f

# ---------------------------------------------------------------------------
# runtime: the same pinned Node, without the package managers. Files are
# owned by root and read-only to the `node` user (uid 1000) the process runs as.
FROM node-base AS runtime
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
ENV NODE_ENV=production
WORKDIR /app
USER node
CMD ["node", "dist/index.js"]

FROM runtime AS identity
COPY --from=builder /out/identity /app
EXPOSE 4001

FROM runtime AS vault
COPY --from=builder /out/vault /app
EXPOSE 4002

FROM runtime AS revocation
COPY --from=builder /out/revocation /app
EXPOSE 4003

FROM runtime AS audit
COPY --from=builder /out/audit /app
EXPOSE 4004

FROM runtime AS dashboard
COPY --from=builder /out/dashboard /app
EXPOSE 4005

# tools: one-off operator commands, run inside the stack's network.
#   custos-migrate   apply infra/migrations to DATABASE_URL
#   custos-admin     API keys (needs DATABASE_URL)
#   custos           the CLI (README step 4)
FROM runtime AS tools
USER root
COPY --from=builder /out/admin /opt/custos/admin
COPY --from=builder /out/cli /opt/custos/cli
COPY infra/migrations/*.sql /opt/custos/migrations/
COPY infra/migrations/meta /opt/custos/migrations/meta
COPY infra/docker/images/migrate.mjs /opt/custos/admin/migrate.mjs
# Wrappers written here, not copied, so a CRLF checkout cannot break them.
RUN printf '#!/bin/sh\nexec node /opt/custos/admin/migrate.mjs "$@"\n' > /usr/local/bin/custos-migrate \
 && printf '#!/bin/sh\nexec node /opt/custos/admin/dist/bin.js "$@"\n' > /usr/local/bin/custos-admin \
 && printf '#!/bin/sh\nexec node /opt/custos/cli/dist/bin.js "$@"\n' > /usr/local/bin/custos \
 && chmod 0755 /usr/local/bin/custos-migrate /usr/local/bin/custos-admin /usr/local/bin/custos \
 && mkdir -p /work && chown node:node /work
WORKDIR /work
USER node
CMD ["custos", "--help"]

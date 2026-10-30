#!/usr/bin/env bash
# `pnpm images:up`: brings the Custos stack up from its images alone (ADR 0019).
#   1. secrets file (env.sh), if missing
#   2. postgres, seal store, redis and the network owner
#   3. migrations, from custos-tools
#   4. API keys, from custos-tools, unless the file already holds active ones
#   5. the services, in dependency order, waiting until each is healthy
#   6. the stand-in tools mock-database and mock-slack stored in the vault,
#      as `pnpm demo` does
# Needs `pnpm images:build` first. Prints no secret.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: leave /opt/... arguments alone

cd "$(dirname "$0")/../../.."
ENV_FILE="infra/docker/images.env"
export CUSTOS_IMAGES_ENV="$ENV_FILE"
compose() {
  docker compose --env-file "$ENV_FILE" -f infra/docker/docker-compose.yml --profile images "$@"
}
KEY_VARS="CUSTOS_OPERATOR_KEY IDENTITY_SERVICE_KEY REVOCATION_SERVICE_KEY VAULT_SERVICE_KEY"

bash infra/docker/images/env.sh

echo "images: starting postgres, seal-store, redis"
compose up -d --wait postgres seal-store redis custos-net

echo "images: migrating"
compose run --rm --no-deps -T tools custos-migrate

# The keys in the file are usable only if the database still holds them
# active (a wiped volume, or expiry, leaves them dangling).
keys_active() {
  local active ids id
  ids=""
  for var in $KEY_VARS; do
    id="$(sed -n "s/^${var}=custos_[a-z]*_\([0-9a-f]\{16\}\)_.*/\1/p" "$ENV_FILE")"
    [ -n "$id" ] || return 1
    ids="$ids $id"
  done
  active="$(compose run --rm --no-deps -T tools custos-admin key list | awk -F'\t' '$3=="active"{print $1}')"
  for id in $ids; do
    printf '%s\n' "$active" | grep -qx "$id" || return 1
  done
}

if keys_active; then
  echo "images: API keys in $ENV_FILE are active"
else
  echo "images: creating API keys (custos-admin dev-keys)"
  created="$(compose run --rm --no-deps -T tools custos-admin dev-keys --shell bash --expires-in 90d)"
  tmp="$ENV_FILE.tmp"
  umask 077
  grep -vE "^($(echo "$KEY_VARS" | tr ' ' '|'))=" "$ENV_FILE" >"$tmp" || true
  printf '%s\n' "$created" | tr -d '\r' | sed -n 's/^export \([A-Z_]*=custos_.*\)$/\1/p' >>"$tmp"
  mv "$tmp" "$ENV_FILE"
  for var in $KEY_VARS; do
    grep -q "^${var}=custos_" "$ENV_FILE" || {
      echo "images: $var was not created" >&2
      exit 1
    }
  done
fi

echo "images: starting services (waits for each to be healthy)"
compose up -d --wait

echo "images: storing stand-in tool credentials"
compose exec -T tools node --input-type=module -e '
const key = process.env.CUSTOS_OPERATOR_KEY;
for (const tool of ["mock-database", "mock-slack"]) {
  const r = await fetch("http://localhost:4002/credentials", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
    body: JSON.stringify({ tool, secret: "any-placeholder-secret" }),
  });
  if (!r.ok) { console.error(`seeding ${tool} failed: vault returned ${r.status}`); process.exit(1); }
}
'

cat <<'EOF'
images: Custos is up from its images.
  dashboard   http://localhost:4005
  identity    http://localhost:4001   vault       http://localhost:4002
  revocation  http://localhost:4003   audit       http://localhost:4004
Run the CLI inside the stack (operator key already set there):
  docker compose --env-file infra/docker/images.env -f infra/docker/docker-compose.yml --profile images exec tools custos --help
Stop: pnpm images:down
EOF

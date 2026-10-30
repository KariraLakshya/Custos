# Shared helpers for the Phase 7 image checks. Sourced, not run.
# Git Bash on Windows rewrites /paths in arguments to docker.exe; stop it.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

# ...so a local file handed to docker.exe needs its Windows path spelled out.
hostpath() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

CHECKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$CHECKS_DIR/../../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/infra/docker/docker-compose.yml"
IMAGES_ENV="${CUSTOS_IMAGES_ENV:-$REPO_ROOT/infra/docker/images.env}"

# Pinned helper image for scanning and self-test fixtures.
HELPER_IMAGE="alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

SERVICE_IMAGES="custos-identity:local custos-vault:local custos-revocation:local custos-audit:local custos-dashboard:local"
ALL_IMAGES="$SERVICE_IMAGES custos-tools:local"

fail_count=0
ok() { printf '  ok   %s\n' "$*"; }
bad() {
  printf '  FAIL %s\n' "$*"
  fail_count=$((fail_count + 1))
}
finish() {
  # $1: check name
  if [ "$fail_count" -eq 0 ]; then
    echo "$1: all assertions passed"
    exit 0
  fi
  echo "$1: $fail_count assertion(s) failed"
  exit 1
}

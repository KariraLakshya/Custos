#!/usr/bin/env bash
# Proves each security check can fail: every check is run against a
# deliberately bad fixture and must fail for the expected reason, and against
# a clean fixture and must pass (so a check that always fails can't pass
# this either). Fixtures are throwaway images and temp files, removed on exit.
# Fake secrets here are random per run; nothing real is used. The PEM header
# is assembled at build time so no private-key block appears in this file.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

work="$(mktemp -d)"
chmod 700 "$work"
fixtures=(custos-selftest-root:local custos-selftest-user:local custos-selftest-dirty:local
  custos-selftest-decoy:local custos-selftest-ignores-env:local custos-selftest-crashes:local custos-selftest-refuses:local)
cleanup() {
  docker image rm -f "${fixtures[@]}" >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT

fake_seed="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
fake_body="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')" # 64 base64-alphabet chars

# build TAG DOCKERFILE-TEXT
build() {
  if ! docker build -q -t "$1" - <<<"$2" >/dev/null 2>"$work/build.err"; then
    bad "could not build fixture $1: $(tail -n3 "$work/build.err")"
    return 1
  fi
}

# expect fail|pass "description" "reason-regex" CHECK ARGS...
expect() {
  local want="$1" what="$2" reason="$3"
  shift 3
  "$@" >"$work/check.out" 2>&1
  local status=$?
  if [ "$want" = fail ]; then
    if [ "$status" -ne 0 ] && grep -Eq -- "$reason" "$work/check.out"; then
      ok "$what: failed as expected ($(grep -Em1 -- "$reason" "$work/check.out" | sed 's/^[[:space:]]*//' | cut -c1-120))"
    else
      bad "$what: expected failure matching /$reason/, got exit $status"
      sed 's/^/       /' "$work/check.out" | head -20
    fi
  else
    if [ "$status" -eq 0 ]; then
      ok "$what: passed as expected"
    else
      bad "$what: expected pass, got exit $status"
      sed 's/^/       /' "$work/check.out" | head -20
    fi
  fi
}

echo "pinned-base"
mkdir -p "$work/df-unpinned" "$work/df-arg" "$work/df-pinned"
printf 'FROM node:22-bookworm-slim\nRUN true\n' >"$work/df-unpinned/Dockerfile"
printf 'FROM ${BASE_IMAGE} AS base\n' >"$work/df-arg/Dockerfile"
cat >"$work/df-pinned/Dockerfile" <<EOF
# syntax=docker/dockerfile:1@sha256:0000000000000000000000000000000000000000000000000000000000000000
ARG BASE=$HELPER_IMAGE
FROM \${BASE} AS build
FROM --platform=linux/amd64 $HELPER_IMAGE AS second
from build
COPY --from=build /etc/hostname /x
FROM scratch
EOF
expect fail "unpinned FROM" "not pinned by @sha256" "$CHECKS_DIR/pinned-base.sh" "$work/df-unpinned"
expect fail "FROM an ARG with no default" "ARG with no default" "$CHECKS_DIR/pinned-base.sh" "$work/df-arg"
mkdir -p "$work/df-syntax" "$work/df-copyfrom"
printf '# syntax=docker/dockerfile:1\nFROM %s\n' "$HELPER_IMAGE" >"$work/df-syntax/Dockerfile"
printf 'FROM %s AS a\nCOPY --from=busybox:latest /bin/sh /x\n' "$HELPER_IMAGE" >"$work/df-copyfrom/Dockerfile"
expect fail "unpinned # syntax= frontend" "frontend image not pinned" "$CHECKS_DIR/pinned-base.sh" "$work/df-syntax"
expect fail "COPY --from an unpinned image" "COPY from busybox:latest" "$CHECKS_DIR/pinned-base.sh" "$work/df-copyfrom"
expect pass "digest-pinned FROMs, stage alias, --platform, scratch" "" "$CHECKS_DIR/pinned-base.sh" "$work/df-pinned"

echo "non-root"
build custos-selftest-root:local "FROM $HELPER_IMAGE" &&
  expect fail "image with no USER (root)" "configured user is" "$CHECKS_DIR/non-root.sh" custos-selftest-root:local
build custos-selftest-user:local "$(printf 'FROM %s\nUSER 1000:1000\n' "$HELPER_IMAGE")" &&
  expect pass "image with USER 1000" "" "$CHECKS_DIR/non-root.sh" custos-selftest-user:local

echo "no-secrets-in-layers"
printf 'SOME_SIGNING_SEED=%s\nDATABASE_URL=postgres://x:y@postgres:5432/z\n' "$fake_seed" >"$work/fake.env"
chmod 600 "$work/fake.env"
dirty="$(cat <<EOF
FROM $HELPER_IMAGE
RUN mkdir -p /app/infra/mtls/certs /app/keys \\
 && echo 'X=1' > /app/.env \\
 && echo 'Y=1' > /app/images.env \\
 && echo 'not a real cert' > /app/infra/mtls/certs/ca.crt \\
 && d=-----; k='PRIVATE KEY'; printf '%sBEGIN %s%s\\n%s\\n%sEND %s%s\\n' "\$d" "\$k" "\$d" "$fake_body" "\$d" "\$k" "\$d" > /app/keys/fake.pem \\
 && echo "const seed = '$fake_seed';" > /app/config.js
USER 1000
EOF
)"
if build custos-selftest-dirty:local "$dirty"; then
  # One scan; each planted item must be reported on its own.
  "$CHECKS_DIR/no-secrets-in-layers.sh" --env-file "$work/fake.env" custos-selftest-dirty:local >"$work/dirty.out" 2>&1
  dirty_status=$?
  for finding in env-file images-env mtls-path private-key secret-value; do
    expect fail "layer with a planted $finding" "FINDING $finding " \
      sh -c 'cat "$1"; exit "$2"' _ "$work/dirty.out" "$dirty_status"
  done
fi
# The header text alone (as in libgnutls, gpgv, jose, npm docs) is not a key.
decoy="$(cat <<EOF
FROM $HELPER_IMAGE
RUN mkdir /app && d=-----; k='PRIVATE KEY'; printf '%sBEGIN %s%s\\n...\\n%sEND %s%s\\n' "\$d" "\$k" "\$d" "\$d" "\$k" "\$d" > /app/docs.md
USER 1000
EOF
)"
build custos-selftest-decoy:local "$decoy" &&
  expect pass "PEM header text without a key body" "" \
    "$CHECKS_DIR/no-secrets-in-layers.sh" --env-file "$work/fake.env" custos-selftest-decoy:local
expect pass "clean image" "" "$CHECKS_DIR/no-secrets-in-layers.sh" --env-file "$work/fake.env" custos-selftest-user:local

echo "missing-secret"
build custos-selftest-ignores-env:local "$(printf 'FROM %s\nUSER 1000\nCMD ["sleep", "60"]\n' "$HELPER_IMAGE")"
build custos-selftest-crashes:local "$(printf 'FROM %s\nUSER 1000\nCMD ["sh", "-c", "echo boom; exit 3"]\n' "$HELPER_IMAGE")"
build custos-selftest-refuses:local "$(printf '%s\n' "FROM $HELPER_IMAGE" "USER 1000" \
  'CMD ["sh", "-c", "if [ -z \"$SOME_SIGNING_SEED\" ]; then printf \"Invalid environment configuration:\\n  - SOME_SIGNING_SEED: required\\n\"; exit 1; fi; sleep 60"]')"
export MISSING_SECRET_LIMIT_SECONDS=6 MISSING_SECRET_CONTROL_SECONDS=3
expect fail "image that boots without its secret" "still running after" \
  "$CHECKS_DIR/missing-secret.sh" "$work/fake.env" custos-selftest-ignores-env:local=SOME_SIGNING_SEED
expect fail "image that crashes without naming the secret" "not with a configuration error" \
  "$CHECKS_DIR/missing-secret.sh" "$work/fake.env" custos-selftest-crashes:local=SOME_SIGNING_SEED
expect pass "image that refuses with a config error" "" \
  "$CHECKS_DIR/missing-secret.sh" "$work/fake.env" custos-selftest-refuses:local=SOME_SIGNING_SEED

finish selftest

#!/usr/bin/env bash
# A service image started without one of its required secrets refuses to
# boot: it exits non-zero within the time limit, its log names the missing
# variable as a configuration error, and it never logs that it is listening.
# Positive control per case: the same image with the full env file does not
# report that configuration error, so the failure is caused by the removal.
#
# Usage: missing-secret.sh [env-file [image=VAR ...]]
#   default env file: infra/docker/images.env; default cases: every required
#   secret of every service image (services/*/src/env.ts, no default value).
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

env_file="${1:-$IMAGES_ENV}"
shift || true
cases=("$@")
if [ "${#cases[@]}" -eq 0 ]; then
  cases=(
    custos-audit:local=AUDIT_SIGNING_SEED
    custos-revocation:local=REVOCATION_SIGNING_SEED
    custos-revocation:local=REVOCATION_SERVICE_KEY
    custos-identity:local=IDENTITY_ISSUER_SEED
    custos-identity:local=IDENTITY_SERVICE_KEY
    custos-vault:local=VAULT_MASTER_KEY
    custos-vault:local=VAULT_SERVICE_KEY
  )
  echo "  n/a  custos-dashboard:local: no required secret (apps/dashboard/src/env.ts)"
fi
LIMIT_SECONDS="${MISSING_SECRET_LIMIT_SECONDS:-30}"
# Config is validated before anything else, so a few seconds show whether it passed.
CONTROL_SECONDS="${MISSING_SECRET_CONTROL_SECONDS:-8}"

if [ ! -f "$env_file" ]; then
  bad "env file not found: $env_file (run pnpm images:up first)"
  finish missing-secret
fi

work="$(mktemp -d)"
chmod 700 "$work"
started=()
cleanup() {
  for c in "${started[@]}"; do docker rm -f "$c" >/dev/null 2>&1; done
  rm -rf "$work"
}
trap cleanup EXIT

# Starts $1 with env file $2; waits until it exits or $3 seconds pass.
# Sets: running (true/false), exit_code, logs, elapsed.
run_and_wait() {
  local image="$1" envf="$2" limit="$3" id start
  id="$(docker run -d --network none --env-file "$(hostpath "$envf")" "$image" 2>"$work/run.err")" || {
    running=false
    exit_code="docker-run-failed"
    logs="$(cat "$work/run.err")"
    elapsed=0
    return
  }
  started+=("$id")
  start=$SECONDS
  running=true
  while [ $((SECONDS - start)) -lt "$limit" ]; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null)" != "true" ]; then
      running=false
      break
    fi
    sleep 1
  done
  elapsed=$((SECONDS - start))
  exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$id" 2>/dev/null)"
  logs="$(docker logs "$id" 2>&1)"
  docker rm -f "$id" >/dev/null 2>&1
}

for spec in "${cases[@]}"; do
  image="${spec%%=*}"
  var="${spec#*=}"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bad "$image without $var: image not found"
    continue
  fi
  if ! grep -q "^${var}=" "$env_file"; then
    bad "$image without $var: $var is not in the env file, so the positive control can't run"
    continue
  fi
  grep -v "^${var}=" "$env_file" >"$work/env"

  run_and_wait "$image" "$work/env" "$LIMIT_SECONDS"
  if [ "$running" = "true" ]; then
    bad "$image without $var: still running after ${LIMIT_SECONDS}s"
  elif [ "$exit_code" = "0" ] || [ "$exit_code" = "docker-run-failed" ]; then
    bad "$image without $var: exit code $exit_code"
  elif ! grep -q "Invalid environment configuration" <<<"$logs" ||
    ! grep -q -- "- ${var}:" <<<"$logs"; then
    bad "$image without $var: exited $exit_code but not with a configuration error naming $var"
  elif grep -qi "listening" <<<"$logs"; then
    bad "$image without $var: logged that it was listening"
  else
    reason="$(grep -m1 -- "- ${var}:" <<<"$logs" | sed 's/^[[:space:]]*//')"
    ok "$image without $var: refused to boot in ${elapsed}s, exit $exit_code ($reason)"
  fi

  # Positive control: with the secret present that configuration error is gone.
  run_and_wait "$image" "$env_file" "$CONTROL_SECONDS"
  if [ "$exit_code" = "docker-run-failed" ]; then
    bad "$image with $var: control container did not start"
  elif grep -q -- "- ${var}:" <<<"$logs"; then
    bad "$image with $var: still reports $var as a configuration error"
  else
    ok "$image with $var: no configuration error for $var (control)"
  fi
done

finish missing-secret

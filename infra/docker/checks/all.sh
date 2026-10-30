#!/usr/bin/env bash
# `pnpm images:check`: every Phase 7 DONE check against the built images and
# the running image stack (`pnpm images:build && pnpm images:up` first).
# Runs every check even after a failure, prints one PASS/FAIL line each, and
# exits non-zero if any failed.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

checks=(selftest pinned-base non-root no-secrets-in-layers missing-secret no-source-mount lifecycle)
results=()
failed=0
for check in "${checks[@]}"; do
  echo "=== $check"
  start=$SECONDS
  if bash "$CHECKS_DIR/$check.sh"; then
    results+=("PASS $check ($((SECONDS - start))s)")
  else
    results+=("FAIL $check ($((SECONDS - start))s)")
    failed=$((failed + 1))
  fi
done

echo "=== summary"
printf '%s\n' "${results[@]}"
if [ "$failed" -gt 0 ]; then
  echo "images:check: $failed of ${#checks[@]} check(s) failed"
  exit 1
fi
echo "images:check: all ${#checks[@]} checks passed"

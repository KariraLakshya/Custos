#!/usr/bin/env bash
# The running image stack uses the images alone: no Custos container has a
# bind mount from the host (so no source checkout reaches it), and each one
# runs the image it was built as.
# Usage: no-source-mount.sh   (against the stack `pnpm images:up` started)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

expected="custos-net:custos-tools tools:custos-tools audit:custos-audit revocation:custos-revocation identity:custos-identity vault:custos-vault dashboard:custos-dashboard"

for pair in $expected; do
  service="${pair%%:*}"
  image="${pair#*:}:local"
  id="$(docker compose -f "$(hostpath "$COMPOSE_FILE")" --profile images ps -q "$service" 2>/dev/null)"
  if [ -z "$id" ]; then
    bad "$service: not running (start the stack with pnpm images:up)"
    continue
  fi
  actual="$(docker inspect -f '{{.Config.Image}}' "$id")"
  if [ "$actual" != "$image" ]; then
    bad "$service: runs '$actual', expected '$image'"
    continue
  fi
  binds="$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}} {{end}}{{end}}' "$id")"
  if [ -n "$binds" ]; then
    bad "$service: bind mount(s) from the host: $binds"
  else
    ok "$service: runs $image with no bind mount"
  fi
done

finish no-source-mount

#!/usr/bin/env bash
# Every image is configured to run as a non-root user, and a process started
# from it really has uid != 0.
# Usage: non-root.sh [image ...]   (default: all six Custos images)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

images=("$@")
[ "${#images[@]}" -eq 0 ] && read -r -a images <<<"$ALL_IMAGES"

for image in "${images[@]}"; do
  if ! user="$(docker image inspect -f '{{.Config.User}}' "$image" 2>/dev/null)"; then
    bad "$image: image not found"
    continue
  fi
  name="${user%%:*}"
  if [ -z "$name" ] || [ "$name" = "0" ] || [ "$name" = "root" ]; then
    bad "$image: configured user is '${user:-<unset, defaults to root>}'"
    continue
  fi
  # Every Custos image has node; fall back to `id` for anything that doesn't.
  uid="$(docker run --rm --network none --entrypoint node "$image" \
    -e 'process.stdout.write(String(process.getuid()))' 2>/dev/null)" ||
    uid="$(docker run --rm --network none --entrypoint id "$image" -u 2>/dev/null)" ||
    uid=""
  uid="${uid//[$'\r\n ']/}"
  if [[ ! "$uid" =~ ^[0-9]+$ ]]; then
    bad "$image: could not read the runtime uid"
  elif [ "$uid" -eq 0 ]; then
    bad "$image: configured user '$user' but runs as uid 0"
  else
    ok "$image: user '$user', runtime uid $uid"
  fi
done

finish non-root

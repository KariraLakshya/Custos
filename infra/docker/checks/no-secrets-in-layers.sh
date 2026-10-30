#!/usr/bin/env bash
# No secret material in any image layer. For each image, `docker save` it and
# unpack every layer (both the classic and the OCI layout, gzip or plain), then
# fail on any of:
#   - a `.env` / `.env.*` file (except *.example, *.sample, *.template)
#   - a file named images.env
#   - anything under an mtls/certs path, or a file byte-identical to one in
#     infra/mtls/certs on this machine
#   - a PEM private key block: a BEGIN ... PRIVATE KEY header line followed by
#     a base64 body line (40+ chars) or a Proc-Type line. The header string
#     alone is not enough: libgnutls, gpgv, jose and npm's docs all contain it
#     as text without holding a key.
#   - any secret value from the env file (keys matching SEED, MASTER_KEY,
#     SERVICE_KEY, OPERATOR_KEY or SECRET, 32+ chars), in a layer or in the
#     image config/history. Values are compared inside the scanner and never
#     printed; only the paths that contain one are.
# The scan runs in a pinned alpine container so it behaves the same on
# Windows and Linux. A layer it cannot unpack fails the check (fail closed).
#
# Usage: no-secrets-in-layers.sh [--env-file F] [image ...]
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

env_file="$IMAGES_ENV"
if [ "${1:-}" = "--env-file" ]; then
  env_file="$2"
  shift 2
fi
images=("$@")
[ "${#images[@]}" -eq 0 ] && read -r -a images <<<"$ALL_IMAGES"

work="$(mktemp -d)"
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT

# Secret values → an env file for the scanner (mode 600, deleted on exit).
: >"$work/values.env"
chmod 600 "$work/values.env"
if [ -f "$env_file" ]; then
  i=0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    key="${line%%=*}"
    value="${line#*=}"
    [[ "$line" == *=* ]] || continue
    [[ "$key" =~ SEED|MASTER_KEY|SERVICE_KEY|OPERATOR_KEY|SECRET ]] || continue
    [ "${#value}" -ge 32 ] || continue
    i=$((i + 1))
    printf 'CUSTOS_SCAN_VALUE_%d=%s\n' "$i" "$value" >>"$work/values.env"
  done <"$env_file"
  echo "  info comparing against $i secret value(s) from $(basename "$env_file") (not printed)"
  [ "$i" -gt 0 ] || bad "no secret values found in $env_file: the value comparison would prove nothing"
else
  bad "env file not found: $env_file — cannot compare secret values"
fi

# Hashes of local mTLS material (public and private), if any exists.
cert_hashes=""
if [ -d "$REPO_ROOT/infra/mtls/certs" ]; then
  # size:hash pairs, so the scanner hashes only files of a matching size.
  while IFS= read -r f; do
    if [ ! -r "$f" ]; then
      # e.g. Envoy's keys, owned by uid 101 (docs: dev:mtls). Still covered
      # by the private-key scan; only the byte-identical comparison is lost.
      echo "  info cannot read $(basename "$f") here; skipped for the identical-file comparison"
      continue
    fi
    cert_hashes="$cert_hashes $(wc -c <"$f" | tr -d ' '):$(sha256sum "$f" | cut -d' ' -f1)"
  done < <(find "$REPO_ROOT/infra/mtls/certs" -type f)
fi

# Runs inside the scanner; reads `docker save` output on stdin.
read -r -d '' SCANNER <<'EOS'
set -u
mkdir -p /s /x
tar -xf - -C /s 2>/dev/null || { echo "ERROR cannot read the docker save stream"; exit 2; }
env | grep '^CUSTOS_SCAN_VALUE_' | cut -d= -f2- > /tmp/values
unset $(env | grep '^CUSTOS_SCAN_VALUE_' | cut -d= -f1)
layers=0
errors=0
n=0
for f in $(find /s -type f); do # blob paths: hex digests, no spaces
  magic=$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')
  n=$((n + 1))
  d=/x/$n
  case "$magic" in
    1f8b*) mode=z ;;
    28b52ffd) echo "ERROR zstd layer, cannot unpack: ${f#/s/}"; errors=$((errors + 1)); continue ;;
    *) if tar -tf "$f" >/dev/null 2>&1; then mode=; else continue; fi ;;
  esac
  mkdir -p "$d"
  echo "${f#/s/}" > "$d.src"
  tar -x${mode}f "$f" -C "$d" 2>/tmp/tar.err || { echo "ERROR some entries of ${f#/s/} did not unpack: $(head -c 200 /tmp/tar.err)"; errors=$((errors + 1)); }
  # Unpacked: scanned under /x from here on, so /s keeps only image metadata.
  rm -f "$f"
  layers=$((layers + 1))
done
echo "INFO unpacked $layers layer(s)"
[ "$layers" -gt 0 ] || { echo "ERROR no layers found"; errors=$((errors + 1)); }
where() { # /x/<n>/<path> -> layer:<blob> /<path>
  rest=${1#/x/}; num=${rest%%/*}; src=$(cat "/x/$num.src" | sed 's|.*/||' | cut -c1-12)
  echo "layer:$src /${rest#*/}"
}
: > /tmp/findings
report() { echo "FINDING $1 $(where "$2")" >> /tmp/findings; }
find /x -type f \( -name '.env' -o -name '.env.*' \) ! -name '*.example' ! -name '*.sample' ! -name '*.template' | while IFS= read -r p; do report env-file "$p"; done
find /x -name 'images.env' | while IFS= read -r p; do report images-env "$p"; done
find /x -path '*mtls/certs*' | while IFS= read -r p; do report mtls-path "$p"; done
grep -rlaE 'BEGIN ([A-Z0-9]+ )*PRIVATE KEY' /x | while IFS= read -r p; do
  # Compiled libraries embed self-test keys (Debian's libgnutls carries GOST
  # test vectors). Listed, not failed: a leaked Custos key arrives as a file.
  if [ "$(head -c 4 "$p" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; then
    echo "INFO pem-in-elf-binary $(where "$p")"
    continue
  fi
  awk '{ sub(/\r$/, "") }
    h { if ($0 ~ /^[A-Za-z0-9+\/=]{40,}$/ || $0 ~ /^Proc-Type:/) { found = 1; exit } if ($0 !~ /^[[:space:]]*$/) h = 0 }
    /BEGIN ([A-Z0-9]+ )*PRIVATE KEY-+[[:space:]]*$/ { h = 1 }
    END { exit !found }' "$p" && report private-key "$p"
done
if [ -s /tmp/values ]; then
  grep -rlaF -f /tmp/values /x /s | while IFS= read -r p; do
    case "$p" in /x/*) report secret-value "$p" ;; *) echo "FINDING secret-value image-metadata:${p#/s/}" >> /tmp/findings ;; esac
  done
fi
if [ -n "${CERT_HASHES:-}" ]; then
  for pair in $CERT_HASHES; do
    find /x -type f -size "${pair%%:*}c" | while IFS= read -r p; do
      [ "$(sha256sum "$p" | cut -d' ' -f1)" = "${pair#*:}" ] && report mtls-file "$p"
    done
  done
fi
cat /tmp/findings
found=$(wc -l < /tmp/findings)
echo "INFO findings=$found errors=$errors"
[ "$found" -eq 0 ] && [ "$errors" -eq 0 ]
EOS

for image in "${images[@]}"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bad "$image: image not found"
    continue
  fi
  docker save "$image" |
    docker run --rm -i --network none --env-file "$(hostpath "$work/values.env")" \
      -e "CERT_HASHES=$cert_hashes" "$HELPER_IMAGE" sh -c "$SCANNER" >"$work/out" 2>&1
  status=$?
  grep -E '^(FINDING|ERROR|WARN|INFO pem)' "$work/out" | sed 's/^/       /' | head -40
  layers="$(sed -n 's/^INFO unpacked \([0-9]*\).*/\1/p' "$work/out")"
  if [ "$status" -eq 0 ]; then
    ok "$image: ${layers:-?} layer(s), no .env, images.env, mTLS certs, private keys or secret values"
  else
    bad "$image: $(grep -c '^FINDING' "$work/out") finding(s), $(grep -c '^ERROR' "$work/out") error(s)"
  fi
done

finish no-secrets-in-layers

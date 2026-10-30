#!/usr/bin/env bash
# Every FROM in the image Dockerfiles is pinned by digest (@sha256:<64 hex>),
# unless it names an earlier build stage or `scratch`.
# Usage: pinned-base.sh [dockerfile-dir]   (default infra/docker/images)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dir="${1:-$REPO_ROOT/infra/docker/images}"
mapfile -t files < <(find "$dir" -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.Dockerfile' \) 2>/dev/null | sort)
if [ "${#files[@]}" -eq 0 ]; then
  bad "no Dockerfiles found under $dir"
  finish pinned-base
fi

for file in "${files[@]}"; do
  declare -A args=()
  declare -A aliases=()
  froms=0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    # Leading whitespace; skip comments and blanks.
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [ -z "$trimmed" ] && continue
    # `# syntax=<image>` pulls a BuildKit frontend image: pinned like a FROM.
    if [ "$froms" -eq 0 ] && [[ "${trimmed,,}" =~ ^#[[:space:]]*syntax[[:space:]]*=[[:space:]]*([^[:space:]]+) ]]; then
      frontend="${BASH_REMATCH[1]}"
      if [[ "$frontend" =~ @sha256:[0-9a-f]{64}$ ]]; then
        ok "$(basename "$file"): # syntax=$frontend — pinned by digest"
      else
        bad "$(basename "$file"): # syntax=$frontend — frontend image not pinned by @sha256 digest"
      fi
      continue
    fi
    [ "${trimmed:0:1}" = "#" ] && continue
    read -r -a words <<<"$trimmed"
    instr="${words[0]^^}"
    # COPY --from=<x> / RUN --mount=...from=<x>: x is an earlier stage or a pinned image.
    if [ "$instr" = "COPY" ] || [ "$instr" = "RUN" ] || [ "$instr" = "ADD" ]; then
      for w in "${words[@]:1}"; do
        src=""
        if [[ "$w" =~ ^--from=(.+)$ ]]; then src="${BASH_REMATCH[1]}"
        elif [[ "$w" =~ ^--mount=.*[,=]from=([^,]+) ]]; then src="${BASH_REMATCH[1]}"
        else continue; fi
        if [ -n "${aliases[${src,,}]+x}" ] || [[ "$src" =~ ^[0-9]+$ ]]; then continue; fi
        if [[ "$src" =~ @sha256:[0-9a-f]{64}$ ]]; then
          ok "$(basename "$file"): $instr from $src — pinned by digest"
        else
          bad "$(basename "$file"): $instr from $src — not an earlier stage and not pinned by @sha256 digest"
        fi
      done
    fi
    if [ "$instr" = "ARG" ] && [ "$froms" -eq 0 ]; then
      # Global ARG with a default: name=value
      spec="${words[1]:-}"
      if [[ "$spec" == *=* ]]; then
        value="${spec#*=}"
        value="${value%\"}"
        value="${value#\"}"
        args["${spec%%=*}"]="$value"
      fi
      continue
    fi
    [ "$instr" = "FROM" ] || continue
    froms=$((froms + 1))
    image=""
    alias=""
    i=1
    while [ "$i" -lt "${#words[@]}" ]; do
      w="${words[$i]}"
      if [[ "$w" == --* ]]; then
        i=$((i + 1))
        continue
      fi
      if [ -z "$image" ]; then
        image="$w"
      elif [ "${w^^}" = "AS" ]; then
        alias="${words[$((i + 1))]:-}"
        break
      fi
      i=$((i + 1))
    done
    # Resolve ${NAME} / $NAME from global ARG defaults.
    resolved="$image"
    while [[ "$resolved" =~ \$\{?([A-Za-z_][A-Za-z0-9_]*)\}? ]]; do
      name="${BASH_REMATCH[1]}"
      if [ -z "${args[$name]+x}" ]; then
        resolved=""
        break
      fi
      resolved="${resolved/"${BASH_REMATCH[0]}"/${args[$name]}}"
    done
    where="$(basename "$file"): FROM $image"
    if [ -z "$resolved" ]; then
      bad "$where — uses an ARG with no default, cannot prove it is pinned"
    elif [ -n "${aliases[${resolved,,}]+x}" ]; then
      ok "$where — earlier build stage"
    elif [ "${resolved,,}" = "scratch" ]; then
      ok "$where — scratch"
    elif [[ "$resolved" =~ @sha256:[0-9a-f]{64}$ ]]; then
      ok "$where — pinned by digest"
    else
      bad "$where — not pinned by @sha256 digest"
    fi
    [ -n "$alias" ] && aliases["${alias,,}"]=1
  done <"$file"
  unset args aliases
  [ "$froms" -eq 0 ] && bad "$(basename "$file"): no FROM line"
done

finish pinned-base

#!/usr/bin/env bash
# The README step 4 lifecycle against the running image stack (`pnpm
# images:up`), entirely inside a custos-tools container that shares the
# services' network namespace: no host Node, no source mount.
#   operator key (custos-admin) → store the stand-in tool passwords →
#   register → verify → use before grant: denied → grant → use: allowed →
#   other tool: denied → deprovision → use: AGENT_REVOKED
# The operator key is created, used and revoked inside the container; it is
# never on a host command line or in this script's output.
#
# Usage: lifecycle.sh
#   LIFECYCLE_NETNS_CONTAINER  container whose network namespace to join
#                              (default: the running container publishing 4001)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TOOLS_IMAGE="${TOOLS_IMAGE:-custos-tools:local}"
owner="${LIFECYCLE_NETNS_CONTAINER:-$(docker ps -q --filter publish=4001 | head -n1)}"
if [ -z "$owner" ]; then
  bad "no running container publishes port 4001: start the stack with pnpm images:up"
  finish lifecycle
fi
if ! docker image inspect "$TOOLS_IMAGE" >/dev/null 2>&1; then
  bad "$TOOLS_IMAGE: image not found"
  finish lifecycle
fi

work="$(mktemp -d)"
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT
# Only DATABASE_URL is needed (custos-admin); take the stack's own value.
: >"$work/tools.env"
chmod 600 "$work/tools.env"
if [ -f "$IMAGES_ENV" ] && grep -q '^DATABASE_URL=' "$IMAGES_ENV"; then
  grep '^DATABASE_URL=' "$IMAGES_ENV" >"$work/tools.env"
else
  echo "DATABASE_URL=postgres://custos:custos@postgres:5432/custos" >"$work/tools.env"
fi

# Runs inside custos-tools (POSIX sh, as the image's non-root user).
read -r -d '' INNER <<'EOS'
set -u
cd "$(mktemp -d)" || exit 2
fails=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fails=$((fails + 1)); }
# run NAME CMD...: stdout → NAME.out, stderr → NAME.err, exit code → rc
run() { name=$1; shift; "$@" >"$name.out" 2>"$name.err"; rc=$?; }
first() { head -n1 "$1" | cut -c1-160; }

run key custos-admin key create --kind operator --name images-lifecycle-check \
  --scopes credentials:write,policies:write,agents:revoke,agents:register --expires-in 1h
key_id=$(sed -n 's/^id: *//p' key.out)
CUSTOS_OPERATOR_KEY=$(sed -n 's/^key: *//p' key.out)
rm -f key.out
if [ "$rc" -ne 0 ] || [ -z "$key_id" ] || [ -z "$CUSTOS_OPERATOR_KEY" ]; then
  bad "custos-admin key create: exit $rc — $(first key.err)"
  exit 1
fi
export CUSTOS_OPERATOR_KEY
trap 'custos-admin key revoke "$key_id" >/dev/null 2>&1 && echo "  info operator key $key_id revoked"' EXIT
ok "custos-admin key create: operator key $key_id"

# README step 3: store the stand-in tool passwords (POST /credentials, as the
# vault's seed script does; that script is not in the tools image).
for tool in mock-database mock-slack; do
  status=$(node -e '
    fetch("http://localhost:4002/credentials", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer " + process.env.CUSTOS_OPERATOR_KEY },
      body: JSON.stringify({ tool: process.argv[1], secret: "any-placeholder-secret" }),
    }).then((r) => console.log(r.status), (e) => console.log("error " + e.message));
  ' "$tool")
  case "$status" in 2??) ok "store credential $tool: HTTP $status" ;; *) bad "store credential $tool: $status" ;; esac
done

run register custos register --out agent.json --key-out agent.key
agent_id=$(node -e 'const a = JSON.parse(require("fs").readFileSync("register.out", "utf8")); process.stdout.write(String(a.id ?? ""))' 2>/dev/null)
agent_did=$(node -e 'const a = JSON.parse(require("fs").readFileSync("register.out", "utf8")); process.stdout.write(String(a.did ?? ""))' 2>/dev/null)
if [ "$rc" -eq 0 ] && [ -n "$agent_id" ] && [ -s agent.json ] && [ -s agent.key ]; then
  ok "register: id $agent_id, did $agent_did"
else
  bad "register: exit $rc — $(first register.err)"
  exit 1
fi
case "$agent_did" in
  did:web:localhost%3A4001:agents:*) ok "register: agent DID is under did:web:localhost%3A4001" ;;
  *) bad "register: unexpected agent DID '$agent_did'" ;;
esac
if grep -q "$(cat agent.key)" register.out register.err; then bad "register: private key printed"; else ok "register: private key not printed"; fi

run verify custos verify agent.json
if [ "$rc" -eq 0 ] && grep -q '^verified: credential is authentic' verify.out; then
  ok "verify: $(first verify.out)"
else
  bad "verify: exit $rc — $(first verify.out) $(first verify.err)"
fi

expect_denied() { # step code tool action input
  step=$1 code=$2
  shift 2
  run "$step" custos use "$1" "$2" --credential agent.json --key agent.key --input "$3"
  if [ "$rc" -ne 0 ] && grep -q "^denied: $code\$" "$step.err" && [ ! -s "$step.out" ]; then
    ok "$step: exit $rc, $(first "$step.err")"
  else
    bad "$step: expected 'denied: $code', got exit $rc — $(first "$step.out") $(first "$step.err")"
  fi
}

expect_denied use-before-grant POLICY_DENIED mock-database query '{"table":"customers"}'

run grant custos grant mock-database --credential agent.json
if [ "$rc" -eq 0 ]; then ok "grant mock-database: exit 0"; else bad "grant: exit $rc — $(first grant.err)"; fi

run use-allowed custos use mock-database query --credential agent.json --key agent.key --input '{"table":"customers"}'
if [ "$rc" -eq 0 ] && grep -q '"result"' use-allowed.out && grep -q 'Ada Lovelace' use-allowed.out && grep -q 'Alan Turing' use-allowed.out; then
  ok "use mock-database after grant: allowed, result has Ada Lovelace and Alan Turing"
else
  bad "use mock-database after grant: exit $rc — $(first use-allowed.out) $(first use-allowed.err)"
fi

expect_denied use-other-tool POLICY_DENIED mock-slack post-message '{"channel":"#ops","text":"hi"}'

run deprovision custos deprovision "$agent_id" --reason "images lifecycle check"
if [ "$rc" -eq 0 ] && grep -Eq '"delivered": *1' deprovision.out; then
  ok "deprovision: exit 0, broadcast delivered 1"
else
  bad "deprovision: exit $rc — $(tr -d '\n' <deprovision.out | cut -c1-200) $(first deprovision.err)"
fi

expect_denied use-after-revoke AGENT_REVOKED mock-database query '{"table":"customers"}'

echo "  info $fails inner failure(s)"
[ "$fails" -eq 0 ]
EOS

echo "  info joining the network namespace of container $(docker inspect -f '{{.Name}}' "$owner" 2>/dev/null)"
docker run --rm -i --network "container:$owner" --env-file "$(hostpath "$work/tools.env")" \
  "$TOOLS_IMAGE" sh -s <<<"$INNER" >"$work/out" 2>&1
status=$?
cat "$work/out"
fail_count=$(grep -c '^  FAIL' "$work/out")
if [ "$status" -ne 0 ] && [ "$fail_count" -eq 0 ]; then
  bad "tools container exited $status"
fi
grep -q '^  ok   use-after-revoke' "$work/out" || [ "$fail_count" -gt 0 ] || bad "lifecycle did not reach the final step"
finish lifecycle
